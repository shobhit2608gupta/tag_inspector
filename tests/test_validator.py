import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'src')
sys.path.insert(0, SRC)

from op_lite.validator import validate_datalayer

def test_validate_success():
    dl = [{'page':{'category':'product','type':'detail'}, 'user':{'loggedIn': True, 'id':'123'}}]
    res = validate_datalayer(dl)
    assert res['valid'] is True

def test_validate_failure():
    dl = [{'page':{'category':'product'}}]
    res = validate_datalayer(dl)
    assert res['valid'] is False
