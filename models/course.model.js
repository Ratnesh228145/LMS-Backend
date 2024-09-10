import { model, Schema } from "mongoose";

  const courseSchema = new Schema({
    title:{
        type:String,
        required: [true, 'Title is required'],
        minLength: [8, 'Title must be atLeast 8 characters'],
        maxLength: [59, 'Title should be less than 60 character'],
        trim: true
    },
    description: {
        type:String,
        required: [true, 'Description is required'],
        minLength: [8, 'Description must be atLeast 8 characters'],
        maxLength: [200, 'Description should be less than 200 character'],
    },
    category: {
        type: String,
        required: [true, 'category is required'],
    },
    thumbnail: {
        public_id : {
            type: String,
            required: true,
        },
        secure_url: {
            type: String,
            required: true,
        }
    },
    lectures: [
        {
            title: String,
            description: String,
            lecture: {
                public_id : {
                    type: String,
                    required: true,
                },
                secure_url: {
                    type: String,
                    required: true
                }
            }
        }
    ],

    numberOfLectures:{
        type: Number,
        default: 0,
    },
    createdBy: {
        type: String,
    }
  },{
    timestamps: true
  });

  const Course = model('Course', courseSchema);

  export default Course;
