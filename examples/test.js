const BroClient = require('../lib/BroClient');
const fs = require('fs');
const _ = require('lodash');
let bro = new BroClient({
    "bro": "/usr/bin/bro",
    "tmp": "/home/jodevsa/broo/",
    "debug": true
});
bro.capture("wlp3s0", () => {
    console.log("started capturing!")
}).on('error', function(log) {
    console.log(log)

}).on("*", function(type, line) {
    //real time
    // could flood anything ur using
    // for example ElasticSearch!
    console.log(line, type);
    //process.exit();
})


let batchCounter = 0;



//// batches , 20 per batch ///////
bro.onBatches(20, {
    // * handler for all event's
    // customize event's before indexing to elastic !
    "*": function(event) {
        //transform id to broid
        ///////////////////////////////////////////////////////////////////
        let keys = Object.keys(event);
        for (let i = 0; i < keys.length; i++) {
            if (keys[i].indexOf("id.") === 0) {
                event[keys[i].replace("id.", "broid.")] = event[keys[i]];
                delete event[keys[i]];
            }

        }
        ///////////////////////////////////////
        event.ts = new Date(event.ts * 1000);
    },
    //connection event handler
    "conn": function(event) {
        event.destIP = event["broid.resp_h"];
        event.destPort = event["broid.resp_p"];
        delete event["broid.resp_p"];
        event.sourceIP = event['broid.orig_h'];
        delete event['broid.orig_h'];
        event.sourcePort = event['broid.orig_p'];
        event.id = event.uid;
        delete event.uid;
    }
    /// next:is  a function that calls for the next batch !
    /// be aware if next is'nt invoked , you'll never get the next batch !!
}).on("*", function(batch, next) {
    console.log("next batch is ready!");
    /// consume batch
    let body = [];
    _.forEach(batch, (item, e) => {
        console.log(item.type);
        console.log(item.data);

        // ok  20 was alot , give me 1 line at a time now  next(1)
      next(1);


    });

}).on("end", function() {
    /// done /////
})
