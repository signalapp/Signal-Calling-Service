//
// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{stream::FusedStream, Stream};
use pin_project::pin_project;

/// The type of [`StreamExt::last`].
///
/// Manually expanded once so you never have to type it again.
#[allow(dead_code)] // Silence the warning about 'pub'; it affects the docs for StreamExt.
pub type Last<S> = futures::stream::Fold<
    S,
    futures::future::Ready<Option<<S as Stream>::Item>>,
    Option<<S as Stream>::Item>,
    fn(
        Option<<S as Stream>::Item>,
        <S as Stream>::Item,
    ) -> futures::future::Ready<Option<<S as Stream>::Item>>,
>;

/// Additional adapters for [`Stream`] in the style of [`futures::StreamExt`].
pub trait StreamExt: futures::StreamExt {
    fn last(self) -> Last<Self>
    where
        Self: Sized,
    {
        self.fold(None, |_, val| futures::future::ready(Some(val)))
    }

    fn latest_only(self) -> LatestOnly<Self>
    where
        Self: Sized,
    {
        LatestOnly(Some(self))
    }
}

impl<S: Stream> StreamExt for S {}

#[cfg(test)]
mod last_tests {
    use async_stream::stream;
    use futures::{
        future::FutureExt,
        pin_mut,
        stream::{empty, iter, pending, StreamExt},
    };

    use super::StreamExt as OurStreamExt;

    #[test]
    fn empty_stream() {
        let stream = empty::<i32>();
        assert_eq!(None, stream.last().now_or_never().unwrap());
    }

    #[test]
    fn pending_stream() {
        let stream = pending::<i32>();
        assert_eq!(None, stream.last().now_or_never());
    }

    #[test]
    fn single() {
        let stream = iter([1]);
        assert_eq!(Some(1), stream.last().now_or_never().unwrap());

        let unfinished_stream = iter([1]).chain(pending());
        assert_eq!(None, unfinished_stream.last().now_or_never());
    }

    #[test]
    fn last() {
        let stream = iter([1, 2, 3]).latest_only();
        assert_eq!(Some(3), stream.last().now_or_never().unwrap());

        let unfinished_stream = iter([1, 2, 3]).chain(pending());
        assert_eq!(None, unfinished_stream.last().now_or_never());
    }

    #[test]
    fn groups() {
        let (sender1, receiver1) = futures::channel::oneshot::channel::<()>();
        let (sender2, receiver2) = futures::channel::oneshot::channel::<()>();
        let last = stream! {
            yield 1i32;
            yield 2;
            receiver1.await.unwrap();
            yield 10;
            yield 20;
            receiver2.await.unwrap();
            yield 100;
            yield 200;
        }
        .last();
        pin_mut!(last);

        assert_eq!(None, last.as_mut().now_or_never());

        sender1.send(()).unwrap();
        // Deliberately send the second signal too; now the groups will be coalesced.
        sender2.send(()).unwrap();

        assert_eq!(Some(200), last.now_or_never().unwrap());
    }
}

#[pin_project]
pub struct LatestOnly<S>(#[pin] Option<S>);

impl<S: Stream> Stream for LatestOnly<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
        match self.as_mut().project().0.as_pin_mut() {
            None => Poll::Ready(None),
            Some(mut inner) => {
                let mut last_val = None;
                loop {
                    match inner.as_mut().poll_next(cx) {
                        Poll::Ready(Some(val)) => {
                            last_val = Some(val);
                        }
                        Poll::Ready(None) => {
                            self.project().0.set(None);
                            return Poll::Ready(last_val);
                        }
                        Poll::Pending => {
                            return if last_val.is_some() {
                                Poll::Ready(last_val)
                            } else {
                                Poll::Pending
                            }
                        }
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            None => (0, Some(0)),
            Some(stream) => {
                let (original_min, max) = stream.size_hint();
                let min = if original_min == 0 { 0 } else { 1 };
                (min, max)
            }
        }
    }
}

impl<S: Stream> FusedStream for LatestOnly<S> {
    fn is_terminated(&self) -> bool {
        self.0.is_none()
    }
}

#[cfg(test)]
mod latest_only_tests {
    use async_stream::stream;
    use futures::{
        future::FutureExt,
        pin_mut,
        stream::{empty, iter, pending, StreamExt},
    };

    use super::{StreamExt as OurStreamExt, *};

    #[test]
    fn empty_stream() {
        let stream = empty::<i32>().latest_only();
        assert_eq!((0, Some(0)), stream.size_hint());
        assert_eq!(
            &[] as &[i32],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );
    }

    #[test]
    fn pending_stream() {
        let mut stream = pending::<i32>().latest_only();
        // The upper bound here is provided by pending().
        assert_eq!((0, Some(0)), stream.size_hint());
        assert_eq!(None, stream.next().now_or_never());
    }

    #[test]
    fn single() {
        let stream = iter([1]).latest_only();
        assert_eq!((1, Some(1)), stream.size_hint());
        assert_eq!(
            &[1],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );

        let mut unfinished_stream = iter([1]).chain(pending()).latest_only();
        assert_eq!(Some(1), unfinished_stream.next().now_or_never().unwrap());
        assert_eq!(None, unfinished_stream.next().now_or_never());
    }

    #[test]
    fn last() {
        let stream = iter([1, 2, 3]).latest_only();
        assert_eq!((1, Some(3)), stream.size_hint());
        assert_eq!(
            &[3],
            &stream.collect::<Vec<_>>().now_or_never().unwrap()[..]
        );

        let mut unfinished_stream = iter([1, 2, 3]).chain(pending()).latest_only();
        assert_eq!(Some(3), unfinished_stream.next().now_or_never().unwrap());
        assert_eq!(None, unfinished_stream.next().now_or_never());
    }

    #[test]
    fn groups() {
        let (sender1, receiver1) = futures::channel::oneshot::channel::<()>();
        let (sender2, receiver2) = futures::channel::oneshot::channel::<()>();
        let stream = stream! {
            yield 1i32;
            yield 2;
            receiver1.await.unwrap();
            yield 10;
            yield 20;
            receiver2.await.unwrap();
            yield 100;
            yield 200;
        }
        .latest_only();
        pin_mut!(stream);

        assert_eq!((0, None), stream.size_hint());
        assert_eq!(Some(2), stream.next().now_or_never().unwrap());
        assert_eq!((0, None), stream.size_hint());
        assert_eq!(None, stream.next().now_or_never());
        assert_eq!((0, None), stream.size_hint());

        sender1.send(()).unwrap();
        // Deliberately send the second signal too; now the groups will be coalesced.
        sender2.send(()).unwrap();

        assert_eq!(Some(200), stream.next().now_or_never().unwrap());
        assert_eq!((0, Some(0)), stream.size_hint());
        assert_eq!(None, stream.next().now_or_never().unwrap());
        assert_eq!((0, Some(0)), stream.size_hint());
    }
}
