# -*- coding: utf-8 -*-
import sys
import time
import os
import re
import prettytable as pt


def main(header,data,times):
    #times刷新次数
    for i in range(times):
      p=pt.PrettyTable()
      #添加表头
      p.field_names=header
      #添加一行数据
      p.add_row(data)
      #清屏操作
      os.system('clear')    
      #输出   
      sys.stdout.write("{0}".format(p))
      sys.stdout.flush() 
      sys.stdout.write("\n")
      time.sleep(0.1)


#######下面是调用###############
times=10
header=['id','name','sex','age']
data=['1','lucy','girl','20']

#构造10个data列表，持续传入main，实现data的原地刷新
for i in range(10):
  data[0]=str(i)
  main(header,data,times)
  
