const fs = require('fs');
const EventEmitter = require('events');
const path = require('path');
const Tail = require('tail-forever')

class watchDir {
    constructor() {
        this._watcher = undefined
        this.emitter=undefined;
    }
     watch(dir, ext) {
      this.emitter=new EventEmitter();
        if (!this._watcher) {
            this._watcher = fs.watch(dir, (eventType, filename) => {
                let fileExt = path.extname(filename.toString())
                let filePath = path.join(dir, filename)

                if (fileExt === ext && eventType === "change" || eventType === "rename") {
                    fs.lstat(filePath, (err, stats) => {
                        if (!err && stats.isFile()) {
                            this.emitter.emit("file", filename);
                        };

                    })
                }
            });

        } else {
            throw ("already watching !");
        }
        return this.emitter;

    }
     unWatch() {
        this._watcher.close();
    }



}

function lsFiles(dir, ext) {
    return new Promise((resolve, reject) => {

        fs.readdir(dir, (err, files) => {
            if (err)
                reject(err)
            let logFiles = [];
            for (i in files) {
                if (path.extname(files[i]) === ext)
                    logFiles.push(files[i]);

            }
            resolve(logFiles)


        });
    });
}
class LogCatcher {
    unWatchAll() {
        console.log(this.tails)
        for (let i = 0; i < this.tails.length; i++) {
            this.tails[i].unwatch();

        }
        this._Watcher.unWatch();

    }
    watch(filename) {
        let fileExt = path.extname(filename.toString())
        let filePath = path.join(this.Location, filename)

        if (this.files.indexOf(filename) == -1) {
            this.files.push(filename);

            let tail = new Tail(filePath, {
                start: 0,
                maxSize: -1,
                maxLineSize: 1024 * 1024 * 20,
                bufferSize: -1,
                encoding: "ascii"

            })
            //this.tail=tail;
            this.tails.push(tail);
            tail.on("line", (data) => {
                this.handleLine(data, filename, fileExt)

            });



        }
    }

    handleLine(data, filename, fileExt) {
        try {
            // buffer size  cause we are reading as buffer too
            let broEventLength = Buffer.byteLength(data, 'utf8')
            //console.log(data.length);
            let broEvent = JSON.parse(data);
            let name = filename.substring(0, filename.length - fileExt.length);
            this.emitter.emit("*.log", {
                "event": broEvent,
                "file": {
                    "full": filename,
                    "name": name,
                    "extinsion": fileExt
                }
            }, broEventLength);
        } catch (ex) {
            console.log(ex)
            console.log("74");
            fs.writeFileSync("error.txt", data);
            console.log(data.length);
            let _p = JSON.parse(data);
            console.log("-----");
            //console.log('error parsing log - not in json format? - ', ex)
            process.exit();
        }





    }
    isWatched(filename) {
        if (this.files.indexOf(filename) == -1) {
            return false;

        } else {
            return true;
        }

    }
    constructor(location) {
        this.tails = [];
        this.files = [];
        this.Location = location;
        this.emitter = new EventEmitter();
        this._Watcher=new watchDir();
        this._Watcher.watch(location, ".log").on("file", (filename) => {
            this.watch(filename);

        });

        lsFiles(this.Location, ".log").then((files) => {
            for (i in files) {
                if (!this.isWatched(files[i])) {
                    this.watch(files[i]);
                }

            }

        })


    }




}

module.exports = LogCatcher;
