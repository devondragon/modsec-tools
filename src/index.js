const { MongoClient } = require('mongodb');
const fs = require('fs');

// Connection URI
const uri =
    "mongodb://localhost:27017/?maxPoolSize=20&w=majority";

const dbName = 'test';
const collectionName = 'modsec4';


async function runSearch(searchString) {
    const client = new MongoClient(uri);
    try {
        // Connect the client to the server
        await client.connect();
        // Establish and verify connection
        await client.db(dbName).command({ ping: 1 });
        console.log("Connected successfully to server. Loading data...");
        const modsec = client.db(dbName).collection(collectionName);

        const results = await modsec.find({
            $text: { $search: "\"" + searchString + "\"" }
        }).sort({ "EntryHeader.date": 1 }).toArray();

        console.log(results.length + ' results found for search string ' + searchString);
        for (const result of results) {
            await parseEntry(result);
        };

    } finally {
        // Ensures that the client will close when you finish/error
        await client.close();
    }
}

async function parseEntry(jsonNode) {
    let date = jsonNode.EntryHeader.date;
    let reqMethod = jsonNode.RequestHeader.method;
    let path = jsonNode.RequestHeader.path;
    let host = jsonNode.RequestHeader.headers.Host;
    let clientIp = jsonNode.RequestHeader.headers["CF-Connecting-IP"];
    let reqCookies = jsonNode.RequestHeader.headers.cookie;
    //let resCookies = jsonNode.ResponseHeader.headers["Set-Cookie"];
    let headersArr = jsonNode.ResponseHeader.headers;

    let resCookies = [];
    if (headersArr != undefined) {
        headersArr.forEach(headerElement => {
            if (headerElement[0] == "Set-Cookie") {
                resCookies.push(headerElement[1]);
                // console.log("headerElement.value: " + headerElement[1]);
            }
        })
    }

    let status = jsonNode.ResponseHeader.status;

    // Use an array of strings as buffer before writing to file
    let fileOutputArray = [];
    let writeLine = (line) => fileOutputArray.push(`\n${line}`);

    let reqJsessionIds = [];
    let resJsessionIds = [];
    if (reqCookies != undefined) {
        let reqCookiesArray = reqCookies.split(';');
        let reqCookiesArrayLength = reqCookiesArray.length;
        for (let i = 0; i < reqCookiesArrayLength; i++) {
            let reqCookie = reqCookiesArray[i];
            let reqCookieArray = reqCookie.split('=');
            let reqCookieName = reqCookieArray[0];
            let reqCookieValue = reqCookieArray[1];
            if (reqCookieName.trim() == 'JSESSIONID') {
                reqJsessionIds.push(reqCookieValue);
            }
        }
    }

    if (resCookies != undefined) {
        console.log("resCookies size: " + resCookies.length);
        resCookies.forEach(resCookie => {
            if (resCookie.includes('JSESSIONID')) {
                resJsessionIds.push(resCookie);
            }
        });
    }

    writeLine(date + ' ' + reqMethod + ' ' + host + path + ' ' + status);
    writeLine('Client IP: ' + clientIp);
    writeLine('Request JSESSION IDs: ');
    for (let i = 0; i < reqJsessionIds.length; i++) {
        let reqJsessionId = reqJsessionIds[i];
        writeLine(reqJsessionId);
    }
    writeLine("");
    writeLine('Response JSESSION IDs: ');
    if (resJsessionIds.length > 1) {
        writeLine('Multiple JSESSION IDs found!!');
        console.log('Multiple JSESSION IDs found!! IP: ' + clientIp);
    }
    for (let i = 0; i < resJsessionIds.length; i++) {
        let resJsessionId = resJsessionIds[i];
        writeLine(resJsessionId);
    }
    writeLine("");
    writeLine("");

    fs.appendFileSync('output/' + clientIp + '.txt', fileOutputArray.join(''));

}



async function get409IPs() {
    const client = new MongoClient(uri);
    try {

        // Connect the client to the server
        await client.connect();
        // Establish and verify connection
        await client.db("test").command({ ping: 1 });
        console.log("Connected successfully to server. Loading data...");
        const modsec = client.db(dbName).collection(collectionName);
        const ipResults = await modsec.find({ "ResponseHeader.status": "409" }, { "RequestHeader.headers.CF-Connecting-IP": 1, _id: 0 }).toArray();
        console.log(ipResults.length + ' 409s found');
        let ipAddyArray = [];
        for (const result of ipResults) {
            if (result != undefined) {
                let ipAddy = result.RequestHeader.headers["CF-Connecting-IP"];
                if (ipAddy != undefined) {
                    ipAddyArray.push(ipAddy.trim());
                }
            }
        };
        console.log(ipAddyArray.length + ' unique IP addresses found');
        let uniqueAndSorted = [...new Set(ipAddyArray)];
        console.log(uniqueAndSorted.length + ' unique IPs found');
        fs.writeFileSync('output/409IPs.txt', uniqueAndSorted.join('\n'));

        for (const ipAddy of uniqueAndSorted) {
            runSearch(ipAddy);
        };
    } finally {
        // Ensures that the client will close when you finish/error
        await client.close();
    }
}



const myArgs = process.argv.slice(2);

if (myArgs.length == 0) {
    get409IPs();
} else {
    runSearch(myArgs[0]).catch(console.dir);
}
