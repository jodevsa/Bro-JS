const EventEmitter = require('events');
const tmp = require('tmp');
const spawn = require('child_process').spawn
const path = require('path');
const fs = require('fs');
const logcatcher = require('./logcatcher');
const _path = require('path');
const async = require('async');
const _ = require('lodash');

// should seperate the bro library and the brorest library (Y)
//technically brorest should inherit from from bro lib (Y)

// simple random shuffle for keys//
function shuffle(a) {
    for (let i = a.length; i; i--) {
        let j = Math.floor(Math.random() * i);
        [a[i - 1], a[j]] = [a[j], a[i - 1]];
    }
}

class BroClient {
    constructor(options) {

        if (typeof(options) != "object") {
            options = {};
        }
        this.options = {};
        this.options.bro = options.bro || "/usr/bin/bro";

        this.options.tmpLocation = options.tmp || "/tmp/";
        this.emitter = new EventEmitter();
        this.totallines = 0;
        this.id = undefined;
        this.filestats = {};
        this.logPath = undefined;
        this._logWatcher = undefined
        this.isRunning = false;
        this.type = undefined;
        this._bro = undefined;
        this.broErrorLog = [];
    }
    _cleanUp() {
        this.emitter.removeAllListeners();
        this.emitter = new EventEmitter();
        this.totallines = 0;
        this.id = undefined;
        this.filestats = {};
        this.logPath = undefined;
        this.isRunning = false;
        this.type = undefined;
        this._bro = undefined;
        this.broErrorLog = []
        this._logWatcher.unWatchAll();
        this._logWatcher.emitter.removeAllListeners();
        this._logWatcher = undefined;
    }



    _getBatch(data_count, cb) {
        let counter = 0;
        let keys = Object.keys(this.filestats);
        shuffle(keys);
        let total = 0;
        let arr = [];
        async.eachSeries(keys, (logType, callback) => {
            if (total === data_count) {
                /// got what we want let's exit!
                return callback();
            }
            let dataStats = this.filestats[logType];

            let available = dataStats.available;
            if (available === 0) {
                /// nothing available in this log , continue to the next one
                return callback();
            }
            let consumed = dataStats.consumed;
            let consume = 0;

            if (available <= (data_count - total)) {
                consume = available
            } else {
                consume = (data_count - total);

            }
            if (consume < 0) {
                throw ("consume is < than 0")
            }
            if (consume === 0) {
                return callback();
            }

            this._consumeLines(consumed, consume, logType, (lines) => {
                this.filestats[logType].available -= lines.data.length;
                this.filestats[logType].consumed += lines.data.length;
                total += consume;
                if (total < 0) {
                    throw ("total is < than 0")
                }

                arr.push({
                    "data": lines.data,
                    "type": logType
                });
                callback();
            });


        }, () => {
            // return the whole array
            return cb(arr, data_count);
        });



    }

    static _get_version(cb) {
        spawn("/usr/bin/bro", ["-v"], {
            cwd: this.logPath
        }).stderr.on("data", (data) => {
            cb(data.toString().split(" ")[2]);

        });


    }


    analyse(pcapLocation, cb) {
        return analyze(pcapLocation, cb);
    }

    analyze(pcapLocation, cb) {
        this.type = "analyse"
        tmp.dir({
            template: path.join(this.options.tmpLocation, 'tmp-XXXXXX')
        }, (err, path, fd, cleanupCallback) => {
            this.logPath = path;
            this._watch();
            this.id = path.split('-')[1];
            this._bro = spawn(this.options.bro, ["-r", _path.resolve(pcapLocation), "-e", "redef LogAscii::use_json=T;"], {
                cwd: path

            }).stderr.on("data", (data) => {
                this.broErrorLog.push(data.toString());
            }).on('close', (code) => {
                this._handleProcessClose(code);

            });

        });
        this.emitter.prependOnceListener("*", () => {
            this.isRunning = true;
            cb();
        })
        return this.emitter;

    }


    stop() {

        if (this._bro && this.isRunning === true)
            this._bro.kill("SIGINT");
        setTimeout(() => {

            this.emitter.emit("end");
        }, 5000);
    }
    watcher() {
        return this.emitter;
    }
    _watch() {
        let b = new logcatcher(this.logPath);
        this._logWatcher = b;
        b.emitter.on('*.log', (e, length) => {
            this.totallines += 1;
            if (this.filestats[e.file.name] === undefined) {
                this.filestats[e.file.name] = {};
                this.filestats[e.file.name].offsets = [length]; //1
                this.filestats[e.file.name].available = 1;
                this.filestats[e.file.name].consumed = 0;


            } else {
                let lastElementLength = this.filestats[e.file.name].offsets[this.filestats[e.file.name].offsets.length - 1] + 1;
                this.filestats[e.file.name].offsets.push(length + lastElementLength);
                this.filestats[e.file.name].available += 1;

            }




            this._emitlog(e);
        })


    }

    _emitlog(e) {
        this.emitter.emit(e.file.name, e.event);
        this.emitter.emit("*", e.file.name, e.event);
    }
    capture(Interface, cb) {
        this.interface = Interface;
        if (this.isRunning === false) {
            tmp.dir({
                template: path.join(this.options.tmpLocation, 'tmp-XXXXXX')
            }, (err, path, fd, cleanupCallback) => {
                if (err) {
                    console.log(err)
                    if (cb)
                        cb(err)
                    return;
                }
                this.logPath = path;
                this._watch();
                this.id = path.split('-')[1];
                this.isRunning = true;
                this._bro = spawn(this.options.bro, ["-i", this.interface, "-e", "redef LogAscii::use_json=T;"], {
                    cwd: this.logPath
                });
                this.running = true;
                this._bro.stderr.on("data", (data) => {
                    let err = data.toString();
                    if (err != undefined)
                        this.broErrorLog.push(err);
                    this.emitter.emit("data", data.toString());
                });
                this._bro.stdout.on("data", (data) => {
                    this.emitter.emit("data", data.toString());
                });
                this._bro.on("close", (code) => {
                    return this._handleProcessClose(code);
                });
                this.emitter.prependOnceListener("*", () => {
                    this.isRunning = true;
                    cb();
                })


            });
            return this.emitter;
        }
    }
    // start from line 0 (including  0 ) up to 99 ---> total 100 (example)
    // logfile *.log ---> ex : conn.log,dns.log,etc..
    _handleProcessClose(code) {
        this.isRunning = false;
        /// due to the fact bro writes everything to stderr
        // it's hard to distinguish between un-intended process halt due to an error and ..
        if (Object.keys(this.filestats).length == 0) {
            this.emitter.emit("error", this.broErrorLog.join("\n"));
            this._cleanUp();
        } else {
            this.emitter.emit("close", code);
        }
    }
    _applyHandlers(batches, handlers) {

        for (let j = 0; j < batches.length; j++) {
            if (handlers["*"] != undefined) {
                for (let i = 0; i < batches[j].data.length; i++) {
                    handlers["*"](batches[j].data[i]);


                }

            }

            if (handlers[batches[j].type] != undefined) {
                for (let i = 0; i < batches[j].data.length; i++) {
                    handlers[batches[j].type](batches[j].data[i]);
                }

            }
        }
    }
    _handleBatchesEmission(batches, emitter) {
        let availalbe_types = [];
        _.forEach(batches, function(batch) {
            let type = batch.type;
            let data = batch.data;
            availalbe_types.push(type);




        })



    }
    onBatches(n, handlers) {
        let counter = 0;
        let batchSize = n;

        let batchEmitter = new EventEmitter();
        let batchRequested = true;
        /////////////////////////////////

        let cache = undefined;
        let next = (size) => {
            // disable for now , a bug was found!
            if (size && false) {
                batchSize = size;
            }
            if (counter >= batchSize) {
                let getCount = batchSize;
                this._getBatch(getCount, (batches) => {

                    if (handlers) {
                        this._applyHandlers(batches, handlers);
                    }


                    counter -= getCount;
                    batchEmitter.emit("*", batches, next)

                })
                batchRequested = false;
            } else {

                batchRequested = true;
            }

        }



        let firstListener = this.emitter.on("*", (data) => {
            counter += 1;
            if (batchRequested && (counter >= batchSize)) {
                let getCount = batchSize;
                batchRequested = false;
                this._getBatch(getCount, (batches) => {
                    if (handlers) {
                        this._applyHandlers(batches, handlers);
                    }
                    this._handleBatchesEmission(batches, batchEmitter);

                    counter -= getCount;
                    batchEmitter.emit("*", batches, next)

                })



            } else {
                if ((batchRequested && (this.isRunning == false)) && counter != 0) {
                    let getCount = counter;
                    this._getBatch(getCount, (batches) => {
                        if (handlers) {
                            this._applyHandlers(batches, handlers);
                        }

                        counter -= getCount;
                        batchEmitter.emit("*", batches, next);


                    })
                    batchRequested = false;


                }
            }

        }).on("end", () => {
            let getCount = 0;
            if (batchRequested && (counter >= batchSize)) {
                getCount = batchSize;
            } else {
                getCount = counter;
            }
            this._getBatch(getCount, (batches) => {
                if (handlers) {
                    this._applyHandlers(batches, handlers);
                }

                counter -= getCount;
                batchEmitter.emit("*", batches, next)
                this._cleanUp();

            })
            batchRequested = false;

        });

        return batchEmitter;

    }
    _consumeLines(n, _count, logFile, cb) {

        if (this.filestats[logFile] === undefined || (n + 1) > this.filestats[logFile].offsets.length) {
            return cb({
                "data": []
            });
        }
        if (this.filestats[logFile].offsets.length === 0) {
            return cb({
                "data": []
            });
        } else {

            let readLine = _count;
            //this does not define it self!
            let current_loc = 0;
            //neither do this.
            let loc = 0;

            let fileLocation = path.join(this.logPath, logFile + ".log");
            fs.open(fileLocation, "r", (status, fd) => {
                //4 with new line
                let previous_loc = 0;
                if (n != 0) {
                    previous_loc = this.filestats[logFile].offsets[n - 1] + 1;
                }

                let t = n + readLine - 1;
                if (this.filestats[logFile].offsets.length <= n + readLine - 1) {
                    current_loc = this.filestats[logFile].offsets[this.filestats[logFile].offsets.length - 1];
                    loc = this.filestats[logFile].offsets.length - 1;
                } else {
                    current_loc = this.filestats[logFile].offsets[(n + readLine - 1)];
                    loc = n + readLine - 1;

                }

                // +2 is for "[" and "]"
                let bufferSize = current_loc - previous_loc + 2;
                let buffer = new Buffer(bufferSize);
                // write from buffer[1], to allow append "[" buffer 0
                let data_buffer_offset = 1;

                fs.read(fd, buffer, data_buffer_offset, current_loc - previous_loc, previous_loc, (err, num) => {
                    fs.close(fd, function() {});
                    if (err) {
                        throw (err)
                    }
                    // 91 ===''['
                    //93 ===']'
                    buffer[0] = 91
                    buffer[bufferSize - 1] = 93;

                    for (let i = n; i < loc; i++) {
                        buffer[this.filestats[logFile].offsets[i] + data_buffer_offset - previous_loc] = 44;

                    }
                    let output = "";
                    try {
                        output = JSON.parse(buffer);
                    } catch (e) {
                        throw e;
                    }

                    return cb({
                        "data": output
                    });

                })
            });
        }
    }
}


module.exports = BroClient;
