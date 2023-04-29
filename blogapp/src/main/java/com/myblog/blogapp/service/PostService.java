package com.myblog.blogapp.service;

import com.myblog.blogapp.payload.PostDto;
import com.myblog.blogapp.payload.PostResponse;

import java.util.List;

public interface PostService {
    PostResponse getAllPosts(int pageNo, int pageSize,String sortBy,String sortDir);

    PostDto createPost(PostDto postDto);

    PostDto getPostById(long id);

    PostDto updatePost(PostDto postDto ,long id);

    void deletePost(long id);
}
