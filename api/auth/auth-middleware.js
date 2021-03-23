const { findBy } = require("../users/users-model")
const bcrypt = require('bcryptjs')
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if(req.session && req.session.user) {
    next()
  } else {
    res.status(401).json({message:'You shall not pass!'})
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
function checkUsernameFree() {
  return async (req, res, next) => {
    try {
      const checkName = await findBy({username: req.body.username})
      if(checkName.length > 0) {
        res.status(422).json({message: 'username taken'})
      } else {
        next()
      }
    } catch (err) {
      next(err)
    }
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
function checkUsernameExists() {
  return async (req, res, next) => {
    try {
      const userExist = await findBy({username: req.body.username})
      if(userExist.length < 1) {
        res.status(401).json({message:'Invalid credentials'})
      } else {
        next()
      }
    } catch (err) {
      next(err)
    }
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  if(req.body.password < 3 || !req.body.password) {
    res.status(422).json({message: 'Password must be longer than 3 chars'})
  } else {
    next()
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
}