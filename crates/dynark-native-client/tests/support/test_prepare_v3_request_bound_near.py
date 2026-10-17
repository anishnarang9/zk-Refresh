import importlib.util
from pathlib import Path
import unittest

source = Path(__file__).with_name('prepare_v3_request_bound_near.py')
spec = importlib.util.spec_from_file_location('prepare_near', source)
near_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(near_module)
one_sibling_delta = near_module.one_sibling_delta


class NearRequestTest(unittest.TestCase):
    def test_same_action_one_sibling_delta(self):
        base = {'root': '1', 'actionHash': '3', 'slot': '44',
                'siblings': ['4'] * 10, 'policyHash': '5'}
        near = {**base, 'root': '2', 'siblings': ['7'] + ['4'] * 9}
        one_sibling_delta(base, near)
        for change in ({**near, 'actionHash': '8'},
                       {**near, 'siblings': ['7', '8'] + ['4'] * 8},
                       {**near, 'slot': '45'},
                       {**near, 'root': '1'}):
            with self.assertRaises(ValueError):
                one_sibling_delta(base, change)


if __name__ == '__main__':
    unittest.main()
