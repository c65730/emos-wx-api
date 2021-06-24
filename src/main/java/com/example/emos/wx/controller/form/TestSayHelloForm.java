package com.example.emos.wx.controller.form;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@ApiModel
@Data
public class TestSayHelloForm {

//    @NotBlank
//    @Pattern(regexp = "^[\\u4e00-\\u9fa5]{2,15}$")
    @ApiModelProperty("姓名")
    private String name;
}
