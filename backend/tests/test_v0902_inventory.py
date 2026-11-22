"""Exercise real inventory handlers with a local SQLite transaction, not RouterOS."""
import ast
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
os.environ.setdefault('DATABASE_URL','sqlite://')
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from fastapi import HTTPException, Depends
from pydantic import BaseModel, Field, ValidationError
from app.models.device import Device
from app.models.device_management import DeviceManagementEvent
from app.schemas.device import DeviceInventory, DeviceOut
from app.core.device_inventory import normalize_inventory, ensure_inventory_columns
from app.services.durations import format_duration

path=Path(__file__).resolve().parents[1]/'app/api/v1/devices.py'
ns=dict(Device=Device,DeviceInventory=DeviceInventory,DeviceOut=DeviceOut,DeviceManagementEvent=DeviceManagementEvent,normalize_inventory=normalize_inventory,Session=Session,User=object,Depends=Depends,get_db=lambda:None,require_role=lambda *r:lambda:None,HTTPException=HTTPException,BaseModel=BaseModel,Field=Field,select=select)
# Extract exact handlers and management helpers; production decorators tested separately by source inspection.
names={'management_lock','record_management','update_inventory','InventoryLocationBatch','bulk_inventory_location'}
nodes=[n for n in ast.parse(path.read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
for n in nodes:n.decorator_list=[]
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)
class Inventory(unittest.TestCase):
 def setUp(self):
  self.engine=create_engine('sqlite://');Device.__table__.create(self.engine);DeviceManagementEvent.__table__.create(self.engine)
  self.db=Session(self.engine);self.user=SimpleNamespace(email='test');self.db.add_all([Device(id=i,name=f'd{i}',host=f'192.0.2.{i}',username='u',password_enc='encrypted',port=8729,use_tls=True,tls_fingerprint='a'*64,comment='original') for i in (1,2)]);self.db.commit()
 def tearDown(self):self.db.close();self.engine.dispose()
 def test_single(self):
  d=ns['update_inventory'](1,DeviceInventory(location='  Серверная  '),self.db,self.user)
  self.assertEqual(d.location,'Серверная');self.assertEqual(d.comment,'original');self.assertEqual(d.password_enc,'encrypted');self.assertEqual(d.tls_fingerprint,'a'*64);self.assertEqual(DeviceOut.model_validate(d).location,'Серверная')
  self.assertEqual(self.db.query(DeviceManagementEvent).one().detail,'location')
 def test_clear(self):
  d=ns['update_inventory'](1,DeviceInventory(comment=' '),self.db,self.user);self.assertIsNone(d.comment)
 def test_noop(self):
  ns['update_inventory'](1,DeviceInventory(comment='original'),self.db,self.user);self.assertEqual(self.db.query(DeviceManagementEvent).count(),0)
 def test_batch(self):
  result=ns['bulk_inventory_location'](ns['InventoryLocationBatch'](ids=[1,2,1],location='Стойка'),self.db,self.user);self.assertEqual(result['count'],2);self.assertTrue(all(d.location=='Стойка' and d.comment=='original' for d in self.db.query(Device)))
 def test_missing_batch_atomic(self):
  with self.assertRaises(HTTPException):ns['bulk_inventory_location'](ns['InventoryLocationBatch'](ids=[1,9],location='changed'),self.db,self.user)
  self.assertIsNone(self.db.get(Device,1).location)
 def test_forbidden_fields(self):
  with self.assertRaises(ValidationError):DeviceInventory(host='wrong')
 def test_limits(self):
  with self.assertRaises(ValidationError):DeviceInventory(comment='x'*4001)
 def test_migration(self):
  engine=MagicMock();ensure_inventory_columns(engine);conn=engine.begin.return_value.__enter__.return_value;self.assertEqual(conn.execute.call_count,4);self.assertTrue(all('ADD COLUMN IF NOT EXISTS' in str(c.args[0]) for c in conn.execute.call_args_list))
 def test_time(self):self.assertEqual(format_duration(62725),'17 ч 25 мин 25 с');self.assertEqual(format_duration(668),'11 мин 8 с');self.assertEqual(format_duration(90061),'1 д 1 ч 1 мин 1 с');self.assertEqual(format_duration(0),'0 с')
