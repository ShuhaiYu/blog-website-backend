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
import Notification from './Schema/Notification.js';
import Comment from './Schema/Comment.js';


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

    const access_token = jwt.sign({ _id: user._id }, process.env.SECRET_ACCESS_KEY, { expiresIn: '1h' });

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

server.get('/', (req, res) => {
    console.log('Received request:', req.method, req.url);
    res.status(200).send('Hello World This is the server for the BlogSpace!');
});

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

server.post("/change-password", verifyJWT, (req, res) => {
    let user_id = req.user;
    let { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(403).json({
            message: 'Please fill out all fields'
        });
    }

    if (!passwordRegex.test(newPassword)) {
        return res.status(403).json({
            message: 'Password must be 6-20 characters, contain at least one digit, one lowercase, and one uppercase letter'
        });
    }

    User.findOne({ _id: user_id }).then((user) => {
        if (user.google_auth) {
            return res.status(403).json({
                message: 'Please change password from Google'
            });
        }
        bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
            if (err) {
                return res.status(500).json({
                    message: err.message
                });
            }
            if (!result) {
                return res.status(403).json({
                    message: 'Old password is incorrect'
                });
            }

            bcrypt.hash(newPassword, 10, (err, hash) => {
                User.findOneAndUpdate({ _id: req.user }, { 'personal_info.password': hash })
                    .then(() => {
                        return res.status(200).json({
                            message: 'Password changed successfully'
                        });
                    })
                    .catch((err) => {
                        return res.status(500).json({
                            message: err.message
                        });
                    });
            });
        });
    })
        .catch(err => {
            return res.status(500).json({
                message: "User not found"
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
    let { tag, query, author, page, limit, eliminate_blog } = req.body;

    let findQuery;

    if (tag) {
        findQuery = { draft: false, tags: tag, blog_id: { $ne: eliminate_blog } };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') };
    } else if (author) {
        findQuery = { draft: false, author };
    }

    let maxLimit = limit ? limit : 2;

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
    let { tag, query, author } = req.body;

    let findQuery;

    if (tag) {
        findQuery = { draft: false, tags: tag };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') };
    } else if (author) {
        findQuery = { draft: false, author };
    }

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

server.post("/search-users", (req, res) => {
    let { query } = req.body;
    User.find({ 'personal_info.username': new RegExp(query, 'i') }).limit(20).select('personal_info.fullname personal_info.username personal_info.profile_img -_id')
        .then((users) => {
            return res.status(200).json({ users });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/get-profile", (req, res) => {
    let { username } = req.body;

    User.findOne({ 'personal_info.username': username })
        .select('-personal_info.password -google_auth -updatedAt -blogs')
        .then(user => {
            return res.status(200).json(user);
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/update-profile-img", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { url } = req.body;

    User.findOneAndUpdate({ _id: user_id }, { 'personal_info.profile_img': url })
        .then(() => {
            return res.status(200).json({
                profile_img: url
            });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/update-profile", verifyJWT, (req, res) => {

    let user_id = req.user;

    let bioLimit = 150;

    let { username, bio, social_links } = req.body;

    if (username.length < 3) {
        return res.status(400).json({
            message: "Username must be at least 3 characters"
        });
    }

    if (username.length > 20) {
        return res.status(400).json({
            message: "Username must be less than 20 characters"
        });
    }

    if (bio.length > bioLimit) {
        return res.status(400).json({
            message: `Bio must be less than ${bioLimit} characters`
        });
    }

    let social_links_keys = Object.keys(social_links);

    try {
        for (let i = 0; i < social_links_keys.length; i++) {
            if (social_links[social_links_keys[i]].length) {
                let hostname = new URL(social_links[social_links_keys[i]]).hostname;
                if (!hostname.includes(`${social_links_keys[i]}.com`) && social_links_keys[i] !== 'website') {
                    return res.status(400).json({
                        message: `Please provide a valid ${social_links_keys[i]} link`
                    });

                }
            }
        }
    } catch (err) {
        return res.status(500).json({
            message: "You must provide full social links with https:// included"
        });
    }

    let UpdateObj = {
        'personal_info.username': username,
        'personal_info.bio': bio,
        social_links
    };

    User.findOneAndUpdate({ _id: user_id }, UpdateObj, { runValidators: true })
        .then(() => {
            return res.status(200).json({
                username
            });
        })
        .catch((err) => {
            if (err.code === 11000) {
                return res.status(409).json({
                    message: "Username already exists"
                });
            }
            return res.status(500).json({
                message: err.message
            });
        });


});


server.post("/create-blog", verifyJWT, (req, res) => {

    let authorId = req.user;

    let { title, banner, content, tags, des, draft, id } = req.body;

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

    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, '-').trim() + '-' + nanoid();

    if (id) {
        Blog.findOneAndUpdate({ blog_id }, { title, banner, content, tags, des, draft: Boolean(draft) })
            .then(() => {
                return res.status(200).json({
                    id: blog_id
                });
            })
            .catch((err) => {
                return res.status(500).json({
                    message: err.message
                });
            });
    } else {
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
    }


});

server.post("/get-blog", (req, res) => {
    let { blog_id, draft, mode } = req.body;

    let incrementVal = mode !== "edit" ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: { 'activity.total_reads': incrementVal } })
        .populate('author', 'personal_info.username personal_info.fullname personal_info.profile_img')
        .select('title banner content tags des publishedAt blog_id activity')

        .then((blog) => {

            User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, { $inc: { 'account_info.total_reads': incrementVal } })
                .catch((err) => {
                    return res.status(500).json({
                        message: "Error updating user's total reads"
                    });
                });

            if (!draft && blog.draft) {
                return res.status(400).json({
                    message: "you can not access draft blogs"
                });
            }
            return res.status(200).json({ blog });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/like-blog", verifyJWT, (req, res) => {

    let user_id = req.user;
    let { _id, isliked } = req.body;

    let incrementVal = !isliked ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, { $inc: { 'activity.total_likes': incrementVal } })
        .then((blog) => {
            if (!isliked) {
                let like = new Notification({
                    type: 'like',
                    blog: _id,
                    notification_for: blog.author,
                    user: user_id
                });
                like.save().then(() => {
                    return res.status(200).json({
                        liked_by_user: true
                    });
                })
                    .catch((err) => {
                        return res.status(500).json({
                            message: err.message
                        });
                    });
            } else {
                Notification.deleteOne({ type: 'like', blog: _id, user: user_id })
                    .then(() => {
                        return res.status(200).json({
                            liked_by_user: false
                        });
                    })
                    .catch((err) => {
                        return res.status(500).json({
                            message: err.message
                        });
                    });


            }
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/isliked-by-user", verifyJWT, (req, res) => {

    let user_id = req.user;
    let { _id } = req.body;

    Notification.exists({ type: 'like', blog: _id, user: user_id })
        .then((result) => {
            return res.status(200).json({
                result
            });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/add-comment", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id, comment, blog_author, replying_to , notification_id} = req.body;

    if (!comment) {
        return res.status(403).json({
            message: 'Write something in comment'
        });
    }

    let newComment = {
        blog_id: _id,
        blog_author,
        comment,
        commented_by: user_id,
    };

    if (replying_to) {
        newComment.isReply = true;
        newComment.parent = replying_to;
    }


    new Comment(newComment).save().then(async (c) => {
        let { commentedAt, comment, children } = c;
        Blog.findOneAndUpdate({ _id }, { $push: { 'comments': c._id }, $inc: { 'activity.total_comments': 1, "activity.total_parent_comments": replying_to ? 0 : 1 } })
            .then((blog) => {
                console.log("new comment added");
            })


        let commentNotification = {
            type: replying_to ? "reply" : 'comment',
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: c._id
        };

        if (replying_to) {
            commentNotification.replied_on_comment = replying_to;
            await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: c._id } })
                .then((replyingToCommentDoc) => {
                    commentNotification.notification_for = replyingToCommentDoc.commented_by;
                })
                .catch((err) => {
                    return res.status(500).json({
                        message: err.message
                    });
                });
            
                if (notification_id){
                    Notification.findOneAndUpdate({_id: notification_id}, {reply: c._id})
                    .then(() => {
                        console.log("reply added to notification");
                    })
                    .catch((err) => {
                        return res.status(500).json({
                            message: err.message
                        });
                    });

                }
        }

        new Notification(commentNotification).save().then((notification) => {
            console.log("new comment notification added");
        })

        return res.status(200).json({
            commentedAt, comment, children, _id: c._id, user_id
        });
    })
});

server.post("/get-blog-comments", (req, res) => {
    let { blog_id, skip } = req.body;

    let maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
        .populate('commented_by', 'personal_info.username personal_info.fullname personal_info.profile_img')
        .skip(skip).limit(maxLimit)
        .sort({ 'commentedAt': -1 })
        .then((comment) => {
            console.log(comment);
            return res.status(200).json(comment);
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/get-replies", (req, res) => {
    let { _id, skip } = req.body;

    let maxLimit = 5;

    Comment.findOne({ _id })
        .populate({
            path: 'children',
            options: {
                skip: skip,
                limit: maxLimit,
                sort: { 'commentedAt': -1 }
            },
            populate: {
                path: 'commented_by',
                select: 'personal_info.username personal_info.fullname personal_info.profile_img'
            },
            select: '-blog_id -updatedAt'
        })
        .select('children')
        .then((doc) => {
            return res.status(200).json({ replies: doc.children });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

const deleteComments = (_id) => {
    Comment.findOneAndDelete({ _id })
        .then((comment) => {
            if (comment.parent) {
                Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
                    .then(() => {
                        console.log("reply deleted");
                    })
                    .catch((err) => {
                        console.log(err.message);
                    });
            }

            Notification.findOneAndDelete({ comment: _id })
                .then(() => {
                    console.log("comment notification deleted");
                })
                .catch((err) => {
                    console.log(err.message);
                });

            Notification.findOneAndUpdate({ reply: _id }, {$unset: {reply: 1}})
                .then(() => {
                    console.log("reply notification deleted");
                })
                .catch((err) => {
                    console.log(err.message);
                });

            Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { 'activity.total_comments': -1, "activity.total_parent_comments": comment.parent ? 0 : -1 } })
                .then(() => {
                    if (comment.children.length > 0) {
                        comment.children.map((child) => {
                            deleteComments(child);
                        });
                    }
                })


        })
        .catch((err) => {
            console.log(err.message);
        });
}

server.post("/delete-comment", verifyJWT, (req, res) => {
    let { _id } = req.body;
    let user_id = req.user;

    Comment.findOne({ _id })
        .then((comment) => {
            if (comment.commented_by == user_id || comment.blog_author == user_id) {
                deleteComments(_id)
                return res.status(200).json({
                    message: 'Comment deleted'
                });
            } else {
                return res.status(403).json({
                    message: 'You can not delete this comment'
                });
            }
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.get("/new-notification", verifyJWT, (req, res) => {
    let user_id = req.user;

    Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
        .then((result) => {
            if (result) {
                return res.status(200).json({
                    new_notification_available: true
                });
            } else {
                return res.status(200).json({
                    new_notification_available: false
                });
            }
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/notifications", verifyJWT, (req, res) => {
    let user_id = req.user;

    let { page, filter, deletedDocCount } = req.body;

    let maxLimit = 10;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } };

    if (filter !== 'all') {
        findQuery.type = filter;
    }

    let skip = (page - 1) * maxLimit;

    if (deletedDocCount) {
        skip -= deletedDocCount;
    }

    Notification.find(findQuery).limit(maxLimit).skip(skip)
        .populate('user', 'personal_info.username personal_info.fullname personal_info.profile_img')
        .populate('blog', 'title blog_id')
        .populate('comment', 'comment')
        .populate('replied_on_comment', 'comment')
        .populate('reply', 'comment')
        .sort({ 'createdAt': -1 })
        .select('createdAt type reply seen')
        .then((notifications) => {
            Notification.updateMany(findQuery, { seen: true })
            .then(() => {
                console.log("notifications updated");
            })
                
            return res.status(200).json({notifications});
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
})

server.post("/all-notifications-count", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { filter } = req.body;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } };

    if (filter !== 'all') {
        findQuery.type = filter;
    }

    Notification.countDocuments(findQuery)
        .then((count) => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/user-written-blogs", verifyJWT, (req, res) => {
    let user_id = req.user;
    let { page, draft, query, deletedDocCount } = req.body;

    let maxLimit = 5;
    let skip = (page - 1) * maxLimit;

    if (deletedDocCount) {
        skip -= deletedDocCount;
    }

    Blog.find({ author: user_id, draft, title: new RegExp(query, 'i') }).limit(maxLimit).skip(skip).sort({ 'publishedAt': -1 })
        .select('blog_id title publishedAt banner activity des draft -_id')
        .then((blogs) => {
            return res.status(200).json({ blogs });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/user-written-blogs-count", verifyJWT, (req, res) => {
    let user_id = req.user;
    let { draft, query } = req.body;

    Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
        .then((count) => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch((err) => {
            return res.status(500).json({
                message: err.message
            });
        });
});

server.post("/delete-blog", verifyJWT, (req, res) => {
    let user_id = req.user;
    let { blog_id } = req.body;

    Blog.findOneAndDelete({ blog_id})
        .then((blog) => {
            Notification.deleteMany({ blog: blog._id }).then(() => {
                console.log("notifications deleted");
            })

            Comment.deleteMany({ blog_id: blog._id }).then(() => {
                console.log("comments deleted");
            })

            User.findOneAndUpdate({ _id: user_id }, { $inc: { 'account_info.total_posts': -1 }, $pull: { "blogs": blog._id } }).then(() => {
               console.log("user updated");
            })

            return res.status(200).json({
                message: "Blog deleted"
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