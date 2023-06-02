import jwt from 'jsonwebtoken';


function generateJWT(user, secret) {
    const payload = {
        id: user.id,
        username: user.username,
    };

    return jwt.sign(payload, secret);
}


function verifyJWT(token,secret) {

    try {
        return jwt.verify(token, secret);
    } catch (error) {
        return false;
    }
}


export {
    generateJWT,
    verifyJWT
}