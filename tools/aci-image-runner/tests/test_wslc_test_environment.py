# Copyright (C) Microsoft Corporation. All rights reserved.

import pathlib
import tempfile
import unittest
from unittest import mock

import wslc_test_environment


class IsolatedProfileTests(unittest.TestCase):
    def test_requires_confirmation_and_actual_local_app_data(self):
        with tempfile.TemporaryDirectory() as directory:
            local = pathlib.Path(directory)
            other = local / "other"
            other.mkdir()
            with mock.patch.object(wslc_test_environment, "local_app_data", return_value=local):
                with self.assertRaisesRegex(ValueError, "dedicated test user"):
                    wslc_test_environment.require_isolated_profile(local, False)
                with self.assertRaisesRegex(ValueError, "actual LocalAppData"):
                    wslc_test_environment.require_isolated_profile(other, True)
                self.assertEqual(
                    wslc_test_environment.require_isolated_profile(local, True),
                    local.resolve() / "wslc-aci",
                )
