# Copyright (C) Microsoft Corporation. All rights reserved.

"""Check that live WSLC tests use an explicitly designated isolated profile."""

import ctypes
import os
import pathlib
import uuid


class Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


def local_app_data():
    if os.name != "nt":
        raise ValueError("live WSLC tests require Windows")
    folder_id = Guid.from_buffer_copy(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le)
    path = ctypes.c_void_p()
    get_folder = ctypes.windll.shell32.SHGetKnownFolderPath
    get_folder.argtypes = [ctypes.POINTER(Guid), ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get_folder.restype = ctypes.c_long
    free = ctypes.windll.ole32.CoTaskMemFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = None
    result = get_folder(ctypes.byref(folder_id), 0, None, ctypes.byref(path))
    if result != 0:
        raise OSError(f"cannot obtain LocalAppData (HRESULT 0x{result & 0xffffffff:08x})")
    try:
        return pathlib.Path(ctypes.wstring_at(path.value))
    finally:
        free(path)


def require_isolated_profile(scratch, confirmed):
    if not confirmed:
        raise ValueError("pass --isolated-profile only for a dedicated test user or VM")
    local = local_app_data().resolve(strict=True)
    if pathlib.Path(scratch).resolve(strict=True) != local:
        raise ValueError("--scratch must be the test user's actual LocalAppData directory")
    return local / "wslc-aci"
