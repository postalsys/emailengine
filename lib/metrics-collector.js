'use strict';

const { threadStats } = require('./tools');

class MetricsCollector {
    constructor(options = {}) {
        this.logger = options.logger || console;
        this.cacheInterval = options.cacheInterval || 10 * 1000; // Default 10 seconds
        this.workerTimeout = options.workerTimeout || 500; // Default 500ms per worker
        this.delayBetweenWorkers = options.delayBetweenWorkers || 50; // Default 50ms between workers
        
        // State management
        this.cachedThreadsInfo = null;
        this.collectorTimer = null;
        this.isCollecting = false;
        this.lastCollectionTime = null;
        
        // Callbacks to get data from main server
        this.getWorkers = options.getWorkers || (() => new Map());
        this.callWorker = options.callWorker || (() => Promise.reject(new Error('callWorker not configured')));
        this.getWorkerMetadata = options.getWorkerMetadata || (() => ({}));
        this.startTime = options.startTime || Date.now();
    }

    /**
     * Start the background metrics collector
     */
    start() {
        // Stop any existing collector
        this.stop();
        
        this.logger.info({ 
            msg: 'Starting background metrics collector', 
            interval: this.cacheInterval,
            delayBetweenWorkers: this.delayBetweenWorkers 
        });
        
        // Collect metrics immediately on start
        this.collectInBackground().catch(err => {
            this.logger.error({ msg: 'Initial metrics collection failed', err });
        });
        
        // Schedule next collection
        this.scheduleNextCollection();
    }

    /**
     * Stop the background metrics collector
     */
    stop() {
        if (this.collectorTimer) {
            clearTimeout(this.collectorTimer);
            this.collectorTimer = null;
        }
        this.isCollecting = false;
        this.logger.info({ msg: 'Stopped background metrics collector' });
    }

    /**
     * Schedule the next metrics collection
     */
    scheduleNextCollection() {
        // Clear any existing timer
        if (this.collectorTimer) {
            clearTimeout(this.collectorTimer);
        }
        
        this.collectorTimer = setTimeout(async () => {
            // Prevent overlapping runs
            if (this.isCollecting) {
                this.logger.debug({ msg: 'Metrics collection still running, rescheduling' });
                this.scheduleNextCollection();
                return;
            }
            
            this.isCollecting = true;
            
            try {
                await this.collectInBackground();
            } catch (err) {
                this.logger.error({ msg: 'Failed to collect metrics in background', err });
            } finally {
                this.isCollecting = false;
                // Schedule next collection after this one completes
                this.scheduleNextCollection();
            }
        }, this.cacheInterval);
    }

    /**
     * Collect metrics in background (sequential to avoid CPU spikes)
     */
    async collectInBackground() {
        const startTime = Date.now();
        
        // Start with main thread info
        let threadsInfo = [
            Object.assign(
                { 
                    type: 'main', 
                    isMain: true, 
                    threadId: 0, 
                    online: this.startTime 
                }, 
                threadStats.usage()
            )
        ];
        
        // Get all workers from the main server
        const workers = this.getWorkers();
        
        // Collect info from all worker threads SEQUENTIALLY to avoid CPU spikes
        for (let [type, workerSet] of workers) {
            if (workerSet && workerSet.size) {
                for (let worker of workerSet) {
                    try {
                        // Query each worker one by one
                        const resourceUsage = await this.callWorker(worker, {
                            cmd: 'resource-usage',
                            timeout: this.workerTimeout
                        });
                        
                        // Get additional metadata for this worker
                        const metadata = this.getWorkerMetadata(worker);
                        
                        let threadData = Object.assign(
                            {
                                type,
                                threadId: worker.threadId,
                                resourceLimits: worker.resourceLimits
                            },
                            resourceUsage,
                            metadata
                        );
                        
                        threadsInfo.push(threadData);
                        
                        // Small delay between workers to spread CPU load
                        if (this.delayBetweenWorkers > 0) {
                            await new Promise(resolve => setTimeout(resolve, this.delayBetweenWorkers));
                        }
                    } catch (err) {
                        // Handle errors gracefully - still include the worker in results
                        const metadata = this.getWorkerMetadata(worker);
                        
                        threadsInfo.push({
                            type,
                            threadId: worker.threadId,
                            resourceLimits: worker.resourceLimits,
                            resourceUsageError: {
                                error: err.message,
                                code: err.code || 'TIMEOUT',
                                unresponsive: err.code === 'Timeout' || err.code === 'CircuitOpen'
                            },
                            ...metadata
                        });
                    }
                }
            }
        }
        
        // Update the cache atomically
        this.cachedThreadsInfo = threadsInfo;
        this.lastCollectionTime = Date.now();
        
        const duration = Date.now() - startTime;
        this.logger.debug({ 
            msg: 'Background metrics collection completed', 
            duration, 
            workers: threadsInfo.length,
            cacheAge: 0
        });
        
        return threadsInfo;
    }

    /**
     * Get thread information (from cache if available)
     * @param {boolean} forceRefresh - Force a fresh collection even if cache exists
     * @returns {Promise<Array>} Array of thread information objects
     */
    async getThreadsInfo(forceRefresh = false) {
        // If we have cached data and don't need to force refresh, return it
        if (!forceRefresh && this.cachedThreadsInfo) {
            const cacheAge = this.lastCollectionTime ? Date.now() - this.lastCollectionTime : null;
            this.logger.debug({ 
                msg: 'Returning cached metrics', 
                workers: this.cachedThreadsInfo.length,
                cacheAge 
            });
            return this.cachedThreadsInfo;
        }
        
        // No cache available or forced refresh - collect synchronously
        this.logger.debug({ msg: 'No cached metrics available or forced refresh, collecting synchronously' });
        
        // For synchronous collection, we still do it sequentially to be safe
        // but we could optionally do parallel collection here if needed for first-time speed
        return await this.collectInBackground();
    }

    /**
     * Get metrics collection statistics
     */
    getStats() {
        return {
            isCollecting: this.isCollecting,
            hasCachedData: !!this.cachedThreadsInfo,
            lastCollectionTime: this.lastCollectionTime,
            cacheAge: this.lastCollectionTime ? Date.now() - this.lastCollectionTime : null,
            cachedWorkerCount: this.cachedThreadsInfo ? this.cachedThreadsInfo.length : 0,
            collectorRunning: !!this.collectorTimer
        };
    }
}

module.exports = MetricsCollector;