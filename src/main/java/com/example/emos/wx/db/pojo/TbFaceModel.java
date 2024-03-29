package com.example.emos.wx.db.pojo;

import lombok.Data;

import java.io.Serializable;

/**
 * sys_config
 * @author 
 */
@Data
public class TbFaceModel implements Serializable {
    /**
     * 主键值
     */
    private Integer id;

    /**
     * 用户ID
     */
    private Integer userId;

    /**
     * 用户人脸模型
     */
    private String faceModel;

    private static final long serialVersionUID = 1L;
}