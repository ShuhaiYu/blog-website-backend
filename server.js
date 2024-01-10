import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import admin from 'firebase-admin';
import { getAuth } from 'firebase-admin/auth';
import aws from 'aws-sdk';




import User from './Schema/User.js';
import serviceAccount from './mern-blog-bc39f-firebase-adminsdk-f8jv6-de3e2c721d.json' assert { type: "json" };
import Blog from './Schema/Blog.js';


const server = express();
let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(cors());
server.use(express.json());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true,
});

// Setting up AWS S3
const s3 = new aws.S3({
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

// Generating a URL for the client to upload a file to AWS S3
const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`

    const params = {
        Bucket: "mern-blog-website-shuhai",
        Key: imageName,
        Expires: 1000,
        ContentType: "image/jpeg",
    };

    return await s3.getSignedUrlPromise('putObject', params);
}

// Verifying JWT
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            message: 'Access token not found'
        });
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({
                message: "Invalid access token"
            });
        }

        req.user = user._id;
        next();
    });

}

const formatDataToSend = (user) => {

    const access_token = jwt.sign({ _id: user._id }, process.env.SECRET_ACCESS_KEY, { expiresIn: '15m' });
    console.log(access_token);

    return {
        access_token,
        fullname: user.personal_info.fullname,
        username: user.personal_info.username,
        profile_img: user.personal_info.profile_img,
    };
}

const generateUsername = async (email) => {
    let username = email.split('@')[0];

    let isUsernameNotUnique = await User.exists({ 'personal_info.username': username }).then((result) => result);

    isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";

    return username;
}

server.get('/get-upload-url', (req, res) => {
    generateUploadURL()
        .then((url) => {
            res.status(200).json({
                uploadURL: url
            });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post('/signup', (req, res) => {
    let { fullname, email, password } = req.body;

    if (!fullname || !email || !password) {
        return res.status(400).json({
            message: 'Please fill out all fields'
        });
    }
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            message: 'Please enter a valid email'
        });
    }
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            message: 'Password must be 6-20 characters, contain at least one digit, one lowercase, and one uppercase letter'
        });
    }

    bcrypt.hash(password, 10, async (err, hash) => {
        let username = await generateUsername(email);

        let newUser = new User({
            personal_info: { fullname, username, email, password: hash },

        });

        newUser.save().then((u) => {

            return res.status(200).json(

                formatDataToSend(u)
            );
        })
            .catch(err => {

                if (err.code == 11000) {
                    return res.status(400).json({
                        message: 'Email already exists'
                    });
                }
                return res.status(500).json({
                    message: err.message
                });
            });

    });
});

server.post('/signin', (req, res) => {
    let { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: 'Please fill out all fields'
        });
    }

    User.findOne({ 'personal_info.email': email }).then((user) => {
        if (!user) {
            return res.status(400).json({
                message: 'Email does not exist'
            });
        }

        if (user.google_auth) {
            return res.status(400).json({
                message: 'Please sign in with Google'
            });
        }

        bcrypt.compare(password, user.personal_info.password, (err, result) => {
            if (err) {
                return res.status(500).json({
                    message: err.message
                });
            }
            if (!result) {
                return res.status(400).json({
                    message: 'Password is incorrect'
                });
            }

            return res.status(200).json(
                formatDataToSend(user),
            );
        });
    })
        .catch(err => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/google-auth", async (req, res) => {


    let { access_token } = req.body;

    getAuth().verifyIdToken(access_token)
        .then(async (decodedToken) => {
            let { name, email, picture } = decodedToken;

            picture = picture.replace('s96-c', 's384-c');

            let user = await User.findOne({ 'personal_info.email': email }).select(
                'personal_info.fullname personal_info.profile_img personal_info.username google_auth'
            )
                .then((u) => {
                    return u || null
                })
                .catch((err) => {
                    return res.status(500).json({
                        message: err.message
                    });
                });

            if (user) {
                if (!user.google_auth) {
                    return res.status(400).json({
                        message: 'Email already exists'
                    });
                }
            } else {
                let username = await generateUsername(email);

                let newUser = new User({
                    personal_info: { fullname: name, username, email },
                    google_auth: true
                });

                await newUser.save().then((u) => {
                    user = u;
                })
                    .catch(err => {
                        return res.status(500).json({
                            message: err.message
                        });
                    });
            }

            return res.status(200).json(
                formatDataToSend(user)
            );
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/latest-blogs", (req, res) => {
    let { page } = req.body;
    let maxLimit = 5;
    Blog.find({ draft: false }).sort({ 'publishedAt': -1 }).limit(maxLimit).skip((page - 1) * maxLimit).select('blog_id title banner des tags publishedAt author activity -_id')
        .populate('author', 'personal_info.fullname personal_info.username personal_info.profile_img -_id')
        .then((blogs) => {
            return res.status(200).json({ blogs });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/count-latest-blogs", (req, res) => {
    Blog.countDocuments({ draft: false })
        .then((count) => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.get("/trending-blogs", (req, res) => {
    Blog.find({ draft: false }).sort({ 'activity.total_reads': -1, "activity.total_likes": -1, 'publishedAt': -1 }).limit(5).select('blog_id title publishedAt author activity -_id')
        .populate('author', 'personal_info.fullname personal_info.username personal_info.profile_img -_id')
        .then((blogs) => {
            return res.status(200).json({ blogs });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/search-blogs", (req, res) => {
    let { tag, page } = req.body;

    let findQuery = { draft: false, tags: tag };

    let maxLimit = 2;

    Blog.find(findQuery).sort({ 'publishedAt': -1 }).limit(maxLimit).select('blog_id title banner des tags publishedAt author activity -_id')
        .skip((page - 1) * maxLimit)
        .populate('author', 'personal_info.fullname personal_info.username personal_info.profile_img -_id')
        .then((blogs) => {
            return res.status(200).json({ blogs });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/count-search-blogs", (req, res) => {
    let { tag } = req.body;

    let findQuery = { draft: false, tags: tag };

    Blog.countDocuments(findQuery)
        .then((count) => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/create-blog", verifyJWT, (req, res) => {

    let authorId = req.user;

    let { title, banner, content, tags, des, draft } = req.body;

    if (!title || title.length > 200) {
        return res.status(400).json({
            message: "Please enter a title less than 200 characters"
        });
    }

    if (!draft) {
        if (!banner || !content.blocks || !des) {
            return res.status(400).json({
                message: 'Please fill out all fields'
            });
        }

        if (des.length > 200) {
            return res.status(400).json({
                message: 'Description must be less than 200 characters'
            });
        }
        if (tags.length > 10) {
            return res.status(400).json({
                message: 'Tags must be less than 10'
            });
        }
        if (content.length > 20000) {
            return res.status(400).json({
                message: 'Content must be less than 10000 characters'
            });
        }
    }


    tags = tags.map((tag) => tag.toLowerCase());

    let blog_id = title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, '-').trim() + '-' + nanoid();

    let blog = new Blog({
        blog_id,
        title,
        banner,
        content,
        tags,
        des,
        draft: Boolean(draft),
        author: authorId
    });

    blog.save().then((b) => {
        let incrementVal = draft ? 0 : 1;

        User.findOneAndUpdate({ _id: authorId }, { $inc: { 'account_info.total_posts': incrementVal }, $push: { "blogs": b._id } })
            .then((u) => {
                return res.status(200).json({
                    id: b.blog_id
                });
            })
            .catch((err) => {
                return res.status(500).json({
                    message: "Error updating user's total posts"
                });
            });
    })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});




server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});