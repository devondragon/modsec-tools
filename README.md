# This is a small collection of tools for working with ModSecurity audit logs

- One Ruby script that converts ModSecurity audit logs to JSON, which can then be imported to MongoDB, and
- A few NodeJS scripts that queries the MongoDB database and generates output text files based on various needs.

Currently there isn't much, and they tools are in difference languages, and were pulled together for a specific investigation, where I needed to first be able to quickly search for various strings that may appear in different portions of the log entries, and then later needed to identify all requests which had multiple cookies with the same name, on the request, and on the response.  

My hope is that the groundwork here, will save other people who need to get data out of modsec audit logs a lot of work, and make customizing queries pretty easy.  Ideally I'd like to evolve and mature this collection of tools to be more powerful and more cohesive.  But perfect is the enemy of good, so here we go!

The first tool is modsec2json.rb, which is a ruby script that parses ModSecurity audit logs and outputs JSON.  I started with this script: https://gist.github.com/labocho/264f37d217543f6aa0e5

Then I made a few changes (removing a duplicate method, adding an EntryHeader parser to get the timestamp, changed how response headers are output to JSON (as an array instead of as a Map, which causes issues with multiple headers with the same name (such as Set-Cookie)), etc... 

The use of this is:  

    ruby modsec2json.rb your_modsec_audit_log.txt > modsec.json

Where it will parse your modsec audit log, and write out to the modsec.json file.

Once we have all the data in JSON format, I loaded it into a MongoDB instance.  You can do this easily enough with a command like:

    mongoimport modsec.json

This will import all the data into a new database, by default named from the file, so in this case "modsec".

Once it is imported, the next step is to create a full text index.  This will allow us to quickly search for any string (IP address, path, response code, etc...).  Run this command in your Mongo database:

    db.getCollection('modsec').createIndex( { "$**": "text" } )

Once it is indexed, you can search quickly and easily within MongoDB.  For example to search for all records with a given IP address, sorted by date:

    db.getCollection('modsec').find({ $text: { $search: "\"192.168.1.158\"" } }).sort( { "EntryHeader.date":1 })

There are also a few NodeJS scripts designed to search for specific things out write output to files.  These were for my specific investigation (around 409s, multiple session cookies, etc...) but you should be able to use them as examples and modify the query and output logic to get what you need.

FWIW: In the example NodeJS scripts, we are using the request header CF-Connecting-IP to get the client IP address, as the site in question is behind CloudFlare.

src/index.js has two functions.  If called with an argument, it will search for that argument string, and then will call the parseEntry method on each entry returned from the search.  In this case it will grab specific data points from the entry object, and write them out to a file in the output directory named with the IP address of the client.  

If called without an argument, it writes out a list of all client IP addresses which saw 409 responses.

src/reqdupfinder.js finds all entries that have duplicate JSESSIONIDs in the request, and writes them all out to files in the output directory named with the IP address of the client.

src/reqdupfinder.js finds all entries that have duplicate JSESSIONIDs in the response, and writes them all out to files in the output directory named with the IP address of the client.


P.S. - I am not a Ruby or NodeJS expert, and much of this was organically created, via trial and error, late at night, so there are probably much better coding practices that could be applied here.  But, it worked and saved me a ton of time and effort, and I wanted to share with you.
