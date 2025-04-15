const Post = require('../models/post');
const jwt = require('jsonwebtoken')
const User = require('../models/user');
const bcrypt = require('bcryptjs')
const validator = require('validator')

module.exports = {
  post: async function ({ postId }, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authenticated');
      error.code = 401
      throw error
    }
    const post = await Post.findById(postId).populate('creator');
    if (!post) {
      const error = new Error("Post not found");
      error.code = 404
      throw error
    }
    return { ...post._doc, _id: post._id.toString(), createdAt: post.createdAt.toISOString(), updatedAt: post.updatedAt.toISOString() }
  },
  posts: async function ({ page }, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authenticated');
      error.code = 401
      throw error
    }
    if (!page) {
      page = 1;
    }
    const postPerPage = 2
    const totalPosts = await Post.find().countDocuments();
    const posts = await Post.find().skip((page - 1) * postPerPage).limit(postPerPage).sort({ createdAt: -1 }).populate('creator')
    return {
      posts: posts.map(p => {
        return {
          ...p._doc,
          _id: p._id.toString(),
          createdAt: p.createdAt.toISOString(),
          updatedAt: p.updatedAt.toISOString()
        }
      }), totalPosts
    }
  },
  createUser: async function ({ userInput }, req) {
    const errors = []
    const email = userInput.email
    const password = userInput.password
    if (!validator.isEmail(email)) {
      errors.push({ message: 'E-Mail is invalid' })
    }
    if (validator.isEmpty(password) || !validator.isLength(password, { min: 4 })) {
      errors.push({ message: 'Invalid Password ' })
    }
    if (errors.length > 0) {
      const error = new Error('Invalid Input')
      error.data = errors;
      error.code = 422;
      throw error
    }
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      const error = new Error('User already exists!!')
      throw error;
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      name: userInput.name,
      password: hashedPassword
    })
    const createdUser = await user.save()
    return { ...createdUser._doc, _id: createdUser._id.toString() }
  },
  createPost: async function ({ postInput }, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authenticated');
      error.code = 401
      throw error
    }
    const errors = []
    if (validator.isEmpty(postInput.title) || validator.isEmpty(postInput.content)) {
      errors.push({ message: 'Invalid Inputs, Empty Fields' })
    }
    if (!validator.isLength(postInput.title, { min: 5 }) || !validator.isLength(postInput.content, { min: 5 })) {
      errors.push({ message: 'Invalid Inputs, Minimum length not reached' })
    }
    if (errors.length > 0) {
      const error = new Error('Invalid Input');
      error.data = errors
      throw error;
    }
    const user = await User.findById(req.userId)
    if (!user) {
      const error = new Error('Invalid User');
      error.code = 401
      throw error;
    }
    const post = new Post({
      title: postInput.title,
      content: postInput.content,
      imageUrl: postInput.imageUrl,
      creator: user
    })
    const createdPost = await post.save()
    user.posts.push(createdPost)
    await user.save()
    return { ...createdPost._doc, _id: createdPost._id.toString(), createdAt: createdPost.createdAt.toISOString(), updatedAt: createdPost.updatedAt.toISOString() }
  },
  login: async function ({ email, password }, req) {
    const user = await User.findOne({ email });
    if (!user) {
      const error = new Error("Invalid Credentials");
      throw error;
    }
    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      const error = new Error("Invalid Credentials");
      throw error;
    }
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        email: user.email
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: '1h' }
    )
    return { token, userId: user._id.toString() }
  },
  updatePost: async function ({ postId, postInput }, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authenticated');
      error.code = 401
      throw error
    }
    const errors = []
    if (validator.isEmpty(postInput.title) || validator.isEmpty(postInput.content)) {
      errors.push({ message: 'Invalid Inputs, Empty Fields' })
    }
    if (!validator.isLength(postInput.title, { min: 5 }) || !validator.isLength(postInput.content, { min: 5 })) {
      errors.push({ message: 'Invalid Inputs, Minimum length not reached' })
    }
    if (errors.length > 0) {
      const error = new Error('Invalid Input');
      error.data = errors
      throw error;
    }
    const post = await Post.findById(postId).populate('creator')
    if (!post) {
      const error = new Error('No post found');
      error.code = 404;
      throw error
    }
    if (post.creator._id.toString() != req.userId.toString()) {
      const error = new Error('Not Authorized');
      error.code = 403;
      throw error
    }
    post.title = postInput.title
    post.content = postInput.content
    if (postInput.imageUrl != 'undefined') {
      post.imageUrl = postInput.imageUrl
    }
    const updatedPost = await post.save()

    return { ...updatedPost._doc, _id: updatedPost._id.toString(), createdAt: updatedPost.createdAt.toISOString(), updatedAt: updatedPost.updatedAt.toISOString() }
  },
  deletePost: async function ({ postId }, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authenticated!!');
      error.code = 401;
      throw error;
    }
    const post = await Post.findByIdAndDelete(postId);
    if (!post) {
      const error = new Error('No post found');
      error.code = 404;
      throw error
    }
    if (post.creator.toString() != req.userId.toString()) {
      const error = new Error('Not Authorized');
      error.code = 403;
      throw error
    }

    const user = await User.findById(req.userId);
    if (!user) {
      const error = new Error("User not found");
      error.code = 404;
      throw error;
    }
    user.posts.pull(postId)
    await user.save()
    return true;

  },
  user: async function (args, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authorized')
      error.code = 401;
      throw error;
    }
    const user = await User.findById(req.userId);
    if (!user) {
      const error = new Error('User not found')
      error.code = 404;
      throw error;
    }
    return { ...user._doc, _id: user._id.toString() }
  }, updateStatus: async function ({ status }, req) {
    if (!req.isAuth) {
      const error = new Error('Not Authorized')
      error.code = 401;
      throw error;
    }
    const user = await User.findById(req.userId);
    if (!user) {
      const error = new Error('User not found')
      error.code = 404;
      throw error;
    }
    user.status = status;
    await user.save()
    return { ...user._doc, _id: user._id.toString() }
  }
}