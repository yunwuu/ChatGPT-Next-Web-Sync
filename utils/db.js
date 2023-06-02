import { createClient } from 'redis';


function getClient(dburl) {
    try {
        const client = createClient({ url: dburl });
        client.on('error', (err) => {
            console.log(err);
        })
        return client;
    } catch {
        return false;
    }
}


export {
    getClient
}