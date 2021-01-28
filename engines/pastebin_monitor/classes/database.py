#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Database class

MIT License

Copyright (c) 2020 Yann Faure - Leboncoin
'''

import sqlite3

class Database:
    '''Database Class'''
    def __init__(self, dbname):
        self.dbname = dbname

    def exec(self, req, args=None):
        '''Execute a sql request'''
        conn = sqlite3.connect(self.dbname)
        sql = conn.cursor()
        if args is None:
            sql.execute(req)
        else:
            sql.execute(req, args)
        conn.commit()
        conn.close()


    def fetchall(self, req, args=None):
        '''Execute a sql request and fetchall'''
        conn = sqlite3.connect(self.dbname)
        sql = conn.cursor()
        if args is None:
            sql.execute(req)
        else:
            sql.execute(req, args)
        conn.commit()
        data = sql.fetchall()
        conn.close()
        return data
