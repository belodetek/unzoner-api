#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from model import engine, Base


if __name__ == '__main__':
    Base.metadata.create_all(engine)
