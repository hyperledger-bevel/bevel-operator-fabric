// Code generated by mockery v2.7.4. DO NOT EDIT.

package mocks

import (
	ecdsa "crypto/ecdsa"

	idemix "github.com/IBM/idemix/bccsp/schemes/dlog/crypto"
	math "github.com/IBM/mathlib"

	mock "github.com/stretchr/testify/mock"
)

// Lib is an autogenerated mock type for the Lib type
type Lib struct {
	mock.Mock
}

// CreateCRI provides a mock function with given fields: key, unrevokedHandles, epoch, alg
func (_m *Lib) CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*math.Zr, epoch int, alg idemix.RevocationAlgorithm) (*idemix.CredentialRevocationInformation, error) {
	ret := _m.Called(key, unrevokedHandles, epoch, alg)

	var r0 *idemix.CredentialRevocationInformation
	if rf, ok := ret.Get(0).(func(*ecdsa.PrivateKey, []*math.Zr, int, idemix.RevocationAlgorithm) *idemix.CredentialRevocationInformation); ok {
		r0 = rf(key, unrevokedHandles, epoch, alg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.CredentialRevocationInformation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*ecdsa.PrivateKey, []*math.Zr, int, idemix.RevocationAlgorithm) error); ok {
		r1 = rf(key, unrevokedHandles, epoch, alg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateLongTermRevocationKey provides a mock function with given fields:
func (_m *Lib) GenerateLongTermRevocationKey() (*ecdsa.PrivateKey, error) {
	ret := _m.Called()

	var r0 *ecdsa.PrivateKey
	if rf, ok := ret.Get(0).(func() *ecdsa.PrivateKey); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*ecdsa.PrivateKey)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewCredential provides a mock function with given fields: key, m, attrs
func (_m *Lib) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*math.Zr) (*idemix.Credential, error) {
	ret := _m.Called(key, m, attrs)

	var r0 *idemix.Credential
	if rf, ok := ret.Get(0).(func(*idemix.IssuerKey, *idemix.CredRequest, []*math.Zr) *idemix.Credential); ok {
		r0 = rf(key, m, attrs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.Credential)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*idemix.IssuerKey, *idemix.CredRequest, []*math.Zr) error); ok {
		r1 = rf(key, m, attrs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewIssuerKey provides a mock function with given fields: AttributeNames
func (_m *Lib) NewIssuerKey(AttributeNames []string) (*idemix.IssuerKey, error) {
	ret := _m.Called(AttributeNames)

	var r0 *idemix.IssuerKey
	if rf, ok := ret.Get(0).(func([]string) *idemix.IssuerKey); ok {
		r0 = rf(AttributeNames)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*idemix.IssuerKey)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(AttributeNames)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RandModOrder provides a mock function with given fields:
func (_m *Lib) RandModOrder() (*math.Zr, error) {
	ret := _m.Called()

	var r0 *math.Zr
	if rf, ok := ret.Get(0).(func() *math.Zr); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*math.Zr)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}