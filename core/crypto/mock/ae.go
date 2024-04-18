// Code generated by mockery. DO NOT EDIT.

package crypto_mock

import (
	crypto "github.com/reshifr/secure-env/core/crypto"
	mock "github.com/stretchr/testify/mock"
)

// AE is an autogenerated mock type for the AE type
type AE struct {
	mock.Mock
}

type AE_Expecter struct {
	mock *mock.Mock
}

func (_m *AE) EXPECT() *AE_Expecter {
	return &AE_Expecter{mock: &_m.Mock}
}

// KeyLen provides a mock function with given fields:
func (_m *AE) KeyLen() uint32 {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for KeyLen")
	}

	var r0 uint32
	if rf, ok := ret.Get(0).(func() uint32); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint32)
	}

	return r0
}

// AE_KeyLen_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyLen'
type AE_KeyLen_Call struct {
	*mock.Call
}

// KeyLen is a helper method to define mock.On call
func (_e *AE_Expecter) KeyLen() *AE_KeyLen_Call {
	return &AE_KeyLen_Call{Call: _e.mock.On("KeyLen")}
}

func (_c *AE_KeyLen_Call) Run(run func()) *AE_KeyLen_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *AE_KeyLen_Call) Return(keyLen uint32) *AE_KeyLen_Call {
	_c.Call.Return(keyLen)
	return _c
}

func (_c *AE_KeyLen_Call) RunAndReturn(run func() uint32) *AE_KeyLen_Call {
	_c.Call.Return(run)
	return _c
}

// Open provides a mock function with given fields: key, buf
func (_m *AE) Open(key []byte, buf []byte) ([]byte, error) {
	ret := _m.Called(key, buf)

	if len(ret) == 0 {
		panic("no return value specified for Open")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte, []byte) ([]byte, error)); ok {
		return rf(key, buf)
	}
	if rf, ok := ret.Get(0).(func([]byte, []byte) []byte); ok {
		r0 = rf(key, buf)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, []byte) error); ok {
		r1 = rf(key, buf)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AE_Open_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Open'
type AE_Open_Call struct {
	*mock.Call
}

// Open is a helper method to define mock.On call
//   - key []byte
//   - buf []byte
func (_e *AE_Expecter) Open(key interface{}, buf interface{}) *AE_Open_Call {
	return &AE_Open_Call{Call: _e.mock.On("Open", key, buf)}
}

func (_c *AE_Open_Call) Run(run func(key []byte, buf []byte)) *AE_Open_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte))
	})
	return _c
}

func (_c *AE_Open_Call) Return(ciphertext []byte, err error) *AE_Open_Call {
	_c.Call.Return(ciphertext, err)
	return _c
}

func (_c *AE_Open_Call) RunAndReturn(run func([]byte, []byte) ([]byte, error)) *AE_Open_Call {
	_c.Call.Return(run)
	return _c
}

// Seal provides a mock function with given fields: iv, key, plaintext
func (_m *AE) Seal(iv crypto.IV, key []byte, plaintext []byte) ([]byte, error) {
	ret := _m.Called(iv, key, plaintext)

	if len(ret) == 0 {
		panic("no return value specified for Seal")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(crypto.IV, []byte, []byte) ([]byte, error)); ok {
		return rf(iv, key, plaintext)
	}
	if rf, ok := ret.Get(0).(func(crypto.IV, []byte, []byte) []byte); ok {
		r0 = rf(iv, key, plaintext)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(crypto.IV, []byte, []byte) error); ok {
		r1 = rf(iv, key, plaintext)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AE_Seal_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Seal'
type AE_Seal_Call struct {
	*mock.Call
}

// Seal is a helper method to define mock.On call
//   - iv crypto.IV
//   - key []byte
//   - plaintext []byte
func (_e *AE_Expecter) Seal(iv interface{}, key interface{}, plaintext interface{}) *AE_Seal_Call {
	return &AE_Seal_Call{Call: _e.mock.On("Seal", iv, key, plaintext)}
}

func (_c *AE_Seal_Call) Run(run func(iv crypto.IV, key []byte, plaintext []byte)) *AE_Seal_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(crypto.IV), args[1].([]byte), args[2].([]byte))
	})
	return _c
}

func (_c *AE_Seal_Call) Return(buf []byte, err error) *AE_Seal_Call {
	_c.Call.Return(buf, err)
	return _c
}

func (_c *AE_Seal_Call) RunAndReturn(run func(crypto.IV, []byte, []byte) ([]byte, error)) *AE_Seal_Call {
	_c.Call.Return(run)
	return _c
}

// NewAE creates a new instance of AE. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAE(t interface {
	mock.TestingT
	Cleanup(func())
}) *AE {
	mock := &AE{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
