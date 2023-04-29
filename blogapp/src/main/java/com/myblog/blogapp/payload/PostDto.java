package com.myblog.blogapp.payload;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class PostDto {
    private Long id;
    @NotNull
    @Size(min = 2,message = "post title atleast 2 character")
    private String title;
    @NotNull
    @Size(min = 10,message = "post description should have atleast 10 character")
    private String description;
    @NotNull
    @NotEmpty
    private String content;
//    @Email
//    @Size(min = 10,max = 10,message = "not valid")
//    private String email;
}
