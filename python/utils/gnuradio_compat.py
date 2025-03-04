#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2025 Fabian P. Schmidt <kerel@mailbox.org>
#
# This file is part of gr-satellites
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from gnuradio import gr


def gnuradio_version_older_than(major: int, api: int, minor: int) -> bool:
    """Compare installed GNURadio version with given version.

    Args:
        major (int): Major version to compare against
        api (int): API version to compare against
        minor (int): Minor version to compare against

    Returns:
        bool: True if installed version is older than given version, False otherwise
    """
    return (
        int(gr.major_version()) <= major and
        int(gr.api_version()) <= api and
        int(gr.minor_version()) < minor
    )
