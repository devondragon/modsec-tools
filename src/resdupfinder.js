const { MongoClient } = require('mongodb');
const fs = require('fs');

// Connection URI
const uri =
    "mongodb://localhost:27017/?maxPoolSize=20&w=majority";

const dbName = 'test';
const collectionName = 'modsec4';



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
        // console.log("resCookies size: " + resCookies.length);
        resCookies.forEach(resCookie => {
            if (resCookie.includes('JSESSIONID')) {
                resJsessionIds.push(resCookie);
            }
        });
    }

    if (resJsessionIds.length > 1) {
        console.log("Found One! " + resJsessionIds.length + " on IP: " + clientIp);
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

}



async function findAllMultipleJsessionIdSets() {
    const client = new MongoClient(uri);
    try {

        // Connect the client to the server
        await client.connect();
        // Establish and verify connection
        await client.db(dbName).command({ ping: 1 });
        console.log("Connected successfully to server. Loading data...");
        const db = client.db(dbName);
        const collection = db.collection(collectionName);
        const cursor = collection.find({});
        while (await cursor.hasNext()) {
            let jsonNode = await cursor.next();
            await parseEntry(jsonNode);
        }


    } finally {
        // Ensures that the client will close when you finish/error
        await client.close();
    }
}



const myArgs = process.argv.slice(2);

if (myArgs.length == 0) {
    findAllMultipleJsessionIdSets();
} else {
    runSearch(myArgs[0]).catch(console.dir);
}
