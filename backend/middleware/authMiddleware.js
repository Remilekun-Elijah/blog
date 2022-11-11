const jwt = require('jsonwebtoken');
require('dotenv').config()
const secretKey = process.env.SECRET_KEY

module.exports = function (req, res, next) {

 // gets the auth token from the req header
 const token = req.headers.authorization;

 try{
  console.log(secretKey);
 // verifies the token
 const decoded = jwt.verify(token, secretKey)
 console.log(decoded)

 res.locals.email = decoded.email

  next()
 } catch (error) {
  console.error(error.name, error.message)
  
  if(error.name === 'JsonWebTokenError') {
     res.status(403).json({success: false, message: "Invalid token"})
  } else if(error.name === 'TokenExpiredError') {
     res.status(401).json({success: false, message: "Token expired"})
  } else {
     res.status(400).json({success: false, message: "Bad token"})
  };
}

 }