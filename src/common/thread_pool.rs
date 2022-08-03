//
// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::Instant;
use flume::{self, Receiver, RecvError, RecvTimeoutError, Sender};
use std::{
    cmp::{Ord, Ordering},
    collections::binary_heap::BinaryHeap,
    thread,
};

pub type Task = Box<dyn FnOnce() + Send + 'static>;

struct ScheduledTask {
    start_time: Instant,
    // Acts as a tie breaker for the start_time
    seqnum: u64,
    task: Task,
}

impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.start_time, other.seqnum).cmp(&(self.start_time, self.seqnum))
    }
}

impl PartialEq for ScheduledTask {
    fn eq(&self, other: &Self) -> bool {
        self.start_time == other.start_time && self.seqnum == other.seqnum
    }
}

impl Eq for ScheduledTask {}

#[derive(Clone)]
pub struct ThreadPool {
    incoming_tasks_sender: Sender<ScheduledTask>,
}

impl ThreadPool {
    pub fn new(thread_count: usize) -> Self {
        assert!(thread_count > 0);
        let (incoming_tasks_sender, incoming_tasks_receiver) = flume::unbounded();

        for _ in 0..thread_count {
            let incoming_tasks_receiver: Receiver<ScheduledTask> = incoming_tasks_receiver.clone();
            let mut next_seqnum = 0u64;
            let _join_handle = thread::spawn(move || {
                let mut scheduled_tasks = BinaryHeap::<ScheduledTask>::new();
                loop {
                    if let Some(scheduled) = scheduled_tasks.peek() {
                        let now = Instant::now();
                        if now > scheduled.start_time {
                            // An optimization to do all the tasks we can before checking the channel more.
                            // Shouldn't fail because we peeked above.
                            if let Some(scheduled) = scheduled_tasks.pop() {
                                (scheduled.task)();
                            }
                        } else {
                            match incoming_tasks_receiver.recv_deadline(scheduled.start_time.into())
                            {
                                Ok(mut incoming_task) => {
                                    incoming_task.seqnum = next_seqnum;
                                    next_seqnum += 1;
                                    scheduled_tasks.push(incoming_task);
                                }
                                Err(RecvTimeoutError::Disconnected) => {
                                    // It's been closed, so stop
                                    return;
                                }
                                Err(RecvTimeoutError::Timeout) => {
                                    // It's time to run scheduled tasks past this start time
                                    // Shouldn't fail because we peeked above.
                                    if let Some(scheduled) = scheduled_tasks.pop() {
                                        (scheduled.task)();
                                    }
                                }
                            }
                        }
                    } else {
                        match incoming_tasks_receiver.recv() {
                            Ok(mut incoming_task) => {
                                incoming_task.seqnum = next_seqnum;
                                next_seqnum += 1;
                                scheduled_tasks.push(incoming_task);
                            }
                            Err(RecvError::Disconnected) => {
                                // It's been closed, so stop
                                return;
                            }
                        }
                    };
                }
            });
        }

        Self {
            incoming_tasks_sender,
        }
    }

    /// Note: tasks can run out of order because they might be scheduled on different threads.
    pub fn spawn_blocking_at(&self, start_time: Instant, task: Task) {
        // Seqnum will be filled in on the other side of the channel.
        let seqnum = 0;
        self.incoming_tasks_sender
            .send(ScheduledTask {
                start_time,
                seqnum,
                task,
            })
            .expect("All of the threads in the thread pool have stopped.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Duration;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_scheduled_task_in_heap() {
        let epoch = Instant::now();
        let mut scheduled_tasks = BinaryHeap::<ScheduledTask>::new();
        scheduled_tasks.push(ScheduledTask {
            start_time: epoch + Duration::from_millis(2),
            seqnum: 1,
            task: Box::new(|| {}),
        });
        scheduled_tasks.push(ScheduledTask {
            start_time: epoch + Duration::from_millis(1),
            seqnum: 2,
            task: Box::new(|| {}),
        });
        scheduled_tasks.push(ScheduledTask {
            start_time: epoch + Duration::from_millis(1),
            seqnum: 3,
            task: Box::new(|| {}),
        });
        assert_eq!(2, scheduled_tasks.pop().unwrap().seqnum);
        assert_eq!(3, scheduled_tasks.pop().unwrap().seqnum);
        assert_eq!(1, scheduled_tasks.pop().unwrap().seqnum);
    }

    #[test]
    fn test_thread_pool() {
        let thread_count = 4;
        let task_count = 1000;
        let task_interval = Duration::from_millis(1);
        let task_iterations = 1000;

        let epoch = Instant::now();
        let task_results = (0..task_count)
            .map(|_| Arc::new(Mutex::new(0)))
            .collect::<Vec<_>>();
        let thread_pool = ThreadPool::new(thread_count);

        for task_iteration_index in 0..task_iterations {
            let start_time = epoch + (task_interval * task_iteration_index);
            for task_result in &task_results {
                let task_result = task_result.clone();
                thread_pool.spawn_blocking_at(
                    start_time,
                    Box::new(move || {
                        let mut task_result = task_result.lock().expect("lock task result");
                        *task_result += 1;
                    }),
                );
            }
            thread::sleep(task_interval.into());
        }

        thread::sleep(Duration::from_millis(200).into());
        drop(thread_pool);

        for task_result in task_results {
            let task_result = task_result.lock().expect("lock task result");
            assert_eq!(*task_result, task_iterations);
        }
    }
}
