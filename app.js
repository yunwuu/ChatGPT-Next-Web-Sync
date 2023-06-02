import express from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import { verifyJWT, generateJWT } from './utils/auth.js';
import { getClient } from './utils/db.js';


// 初始化
dotenv.config();
const app = express();
app.use(bodyParser.json());
const PORT = process.env.port || 3000;

// 环境检查
if (!process.env.jwtsecret) throw new Error('No jwtsecret found');
if (!process.env.dburl) throw new Error('DB url not found.');


// 处理 Auth Header
function verifyAuthHeader(req, res) {
    const authHeader = req.headers['Authorization'] || req.headers['authorization'];
    if (!authHeader) return res.status(500).json({ code: -1, errmsg: 'No auth header.' });
    const token = authHeader.split(' ')[1];
    console.log(`Received token: ${token}`);
    if (!token) return res.status(500).json({ code: -2, errmsg: 'Auth header is invalid.' });
    const verify = verifyJWT(token, process.env.jwtsecret);
    if (!verify) return res.status(401).json({ code: -3, errmsg: 'Unauthorized' });
    return false; // header有效
} 


// 获取用户信息
app.get('/user', async (req, res) => {
    const verifyResult = verifyAuthHeader(req, res);
    if (!verifyResult) 
      return res.status(200).json({ code: 0, result: verify });
    else
      return verifyResult;
})


// 登录获取Token
app.post('/login', async (req, res) => {
    const id = req.body.uid;
    const pwd = req.body.pwd;
    if (!id || !pwd) return res.status(500).json({ code: -1, errmsg: 'uid and/or password not found.' })
    // ... 查数据库 => username
    const username = 'test'; 
    return res.json({ code: 0, result: generateJWT({id, pwd}, process.env.jwtsecret) });
})


// 初始化用户数据表
app.get('/user/init', async (req, res) => {
    const authHeader = req.headers['Authorization'] || req.headers['authorization'];
    if (!authHeader) return res.status(500).json({ code: -1, errmsg: 'No auth header.' });
    const token = authHeader.split(' ')[1];
    console.log(`Received token: ${token}`);
    if (!token) return res.status(500).json({ code: -2, errmsg: 'Auth header is invalid.' });
    const verify = verifyJWT(token, process.env.jwtsecret);
    if (!verify) return res.status(401).json({ code: -3, errmsg: 'Unauthorized' });
})


app.listen(PORT, '0.0.0.0', () => {
    console.log(`App is listening on port ${PORT}`);
})