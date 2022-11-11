const express = require("express");
const bcrypt = require("bcryptjs")
const authMiddleware = require("./middleware/authMiddleware")
const jwt = require("jsonwebtoken");
const cors = require("cors")
require('dotenv').config()

const Database = require("./database")
const app = express()


const postRoute = require("./blog");

const salt = bcrypt.genSaltSync()
const port = process.env.PORT || 7000;

app.use(express.json())
app.use(express.urlencoded({
   extended: false
}))
app.use(cors())

app.use("/post", postRoute)

const secretKey = process.env.SECRET_KEY




function createUserHandler(req, res) {
   const newUser = req.body;

   const userEmail = Database.users.filter((user) => newUser.email === user.email)

   if (userEmail.length !== 0) {
      res.status(409).json({
         message: "User already exist",
         success: false
      })
   } else {
      const password = newUser.password
      const hash = bcrypt.hashSync(password, salt);
      newUser.password = hash;
      Database.users.push(newUser);
      res.status(201).json({
         message: "User created successfully",
         success: true
      });
   }
}

const getUsers = (req, res) => {
   res.status(200).json({
      message: 'User Gotten',
      data: Database.users
   })
}

const getUser = (req, res) => {
   // gets the email from locals
   const email = res.locals.email;

   // gets the user from teh database
   const usersData = Database.users.find(res => res.email === email)

   if (usersData) {
      // deletes password field from the object
      delete usersData.password

      res.status(200).json({
         message: 'User detail retrieved successfully',
         data: usersData
      })

   } else {
      res.status(404).json({
         success: false,
         message: "User not found in the system"
      })
   }
}

function authMiddleWare (req, res, next) {
   const token = req.headers.authorization;
   try {
      const decoded = jwt.verify(token, secretKey)
      console.log(decoded.email);
      // attaches the email to res object
      res.locals.email = decoded.email;
      // moves the request to the next middleware in line
      next()
   } catch (error) {
      console.error(error);
      res.status(401).json({
         success: false,
         message: "Invalid token",
         error: error.message
      })
   }

}

app.get('/user', authMiddleWare, getUser)

app.get('/users', getUsers)

let userLogin = (req, res) => {
   let {
      email,
      password
   } = req.body
   if (email == '' || password == '') {
      res.status(401).json({
         success: false,
         message: "please input email or password"
      })
   } else {
      let userExist = Database.users.filter(user => user.email === email)
      if (userExist.length == 0) {
         res.status(404).json({
            success: false,
            message: "User not found"
         })
      } else {
         if (bcrypt.compareSync(password, userExist[0].password)) {
            const token = jwt.sign({
               email
            }, secretKey, {
               expiresIn: '5d'
            })

            res.status(200).json({
               success: true,
               message: "User logged in successfully",
               token
            })
         } else {
            res.status(404).json({
               success: false,
               message: "Oops! wrong user"
            })
         }
      }
   }
}


function updateUser(req, res) {
   const decoded = res.locals
   if (decoded.email) {
      const userIndex = Database.users.findIndex(item => item.email === decoded.email)

      if (userIndex < 0) {
         res.status(401).send("User not found")
      } else {
         const updateUser = {
            ...Database.users[userIndex],
            ...req.body
         };

         Database.users[userIndex] = updateUser;
         res.status(200).json({
            status: "success",
            message: "Profile updated successfully"
         })
      }
   }
}

app.put("/users/update", authMiddleware, updateUser)


app.post('/auth/signup', createUserHandler)

app.post("/auth/login", userLogin)





app.listen(port, () => console.log("Server started on port", port))