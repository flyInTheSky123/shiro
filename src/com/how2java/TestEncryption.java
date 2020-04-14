package com.how2java;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.junit.Test;

//md5加密
public class TestEncryption {
    @Test
    public void encryption(){
        String password="1234";
        //经过md5（非对称加密） 后的密码
        String s1 = new Md5Hash(password).toString();
        System.out.println("s:"+s1);
        //s:81dc9bdb52d04dc20036dbd8313ed055

    }

    //salt：就像是炒菜，材料一样，但是放的盐 量不一样 味道就不一样了。这是使用"盐" 进行添加加密。
    //将salt(盐） ,time （加密次数）,md5，一起加密源码。
    @Test
    public void encryptionWithSalt(){
        String password="1234";   //密码
        String salt = new SecureRandomNumberGenerator().nextBytes().toString(); //盐
        String name="md5";
        int times=2;

                                 //加密方式，密码，盐，次数。
        String s = new SimpleHash(name, password, salt, times).toString();

        System.out.println("加密后的密码是： "+s);
        //加密后的密码是： 10a7693b2e10e8e8beb6ad470e5649b5


    }
}
