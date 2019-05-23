
# Bro IDS Nodejs Library
### Why i did it! :
I'm doing a project that involves analyzing  many pcap's using the great Bro IDS with aid of ElasticSearch
#### Problems encountered using BRO in my poject:
* BRO does not  have any programmable interface that i can make use of.
* all output from Bro is saved to files. ex:"conn.log","http.log", etc...

#### Why not just use LogStash ?
 At First glance logstash appeared to be the soloution to my problem, after tinkering with it i knew i was wrong.
 Indeed logstash provide's  great config utilities that customize's the way it eat's logs's, i needed more control ! ; to me it i felt like it was built for system administrator's use only .
 * logstash config language is custom tailered; you can't parse the config and dynamically change it
 * don't have any programmable interface (as far as i know )



 ### Features:
 * Ability to consume realtime data from bro
 * Ability to consume data on batch bases from bro
 * control bro process from NodeJS


### Examples:

#### Example 1: listening on a network interface and consuming real-time data ( as soon as bro write's it to disk)
```
const BroClient = require('../lib/BroClient');
const _ = require('lodash');
// By default bro always spawn the /usr/bin/bro process, if you have  bro installed else-where //change "bro" attribute .
//By default all logs are written to /tmp library , change it with the "tmp" attribute.
let bro = new BroClient({
    "bro": "/usr/bin/bro",
    "tmp": "/home/jodevsa/broo/"
});
// listen on 'wlp3s0' interface
bro.capture("wlp3s0",()=>{
    console.log("started capturing on interface wlp3s0");
}).on("*",function(type,line){
    // for example "conn"
    console.log("log Type",type);
    console.log(line);
    /*{"ts":1133502567.143497,"uid":"CWKgyN4kUBiM0FRbFd","id.orig_h":"192.168.0.112","id.orig_p":12345,"id.resp_h":"178.20.343.5","id.resp_p":443,"proto":"tcp","conn_state":"OTH","missed_bytes":0,"history":"C","orig_pkts":0,"orig_ip_bytes":0,"resp_pkts":0,"resp_ip_bytes":0,"tunnel_parents":[]}
    */
}).on("http",(line)=>{
        //or if we are only interested in http logs
        console.log(line);
});
```

#### Example 2: Analyzing an already capture pcap and consuming logs on batches:
```
const BroClient = require('../lib/BroClient');
const _ = require('lodash');
let bro = new BroClient({
    "bro": "/usr/bin/bro",
    "tmp": "/home/jodevsa/broo/"
});
// listen on 'wlp3s0' interface
bro.analyze("/home/broworkstation/Desktop/mynetwork.pcap",()=>{
    console.log("started analyzing mynetwork.pcap");
})
bro.onBatches(20, {
    // * handler for all event's
    // customize event's before emitting to the main listener "*"
    // inspired from logstash config language
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
        // convert event.ts to date object
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
    /// be aware if next isn't invoked , you'll never get the next batch !!
}).on("*", function(batch, next) {
    console.log("next batch is ready!");
    /// consume batch
    let body = [];
    _.forEach(batch, (item, e) => {
        console.log(item.type);
        //contains all lines of the same item.type
        console.log(item.data);

        // ok  20 was alot , give me 1 line at a time now  next(1)
        next(1);


    });

}).on("end", function() {
    /// done /////
})
```
### to be continued !!!
