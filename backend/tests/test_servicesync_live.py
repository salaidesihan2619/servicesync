"""Live regression coverage for ServiceSync authentication, garage, bookings, and reviews."""
import os
import uuid

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
STAFF = {"email": "staff@servicesync.com", "password": "staff123"}


@pytest.fixture(scope="module")
def api():
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    return session


@pytest.fixture(scope="module")
def customer(api):
    email = f"TEST_{uuid.uuid4().hex[:10]}@example.com"
    response = api.post(f"{BASE_URL}/api/auth/register", json={
        "name": "TEST Customer", "email": email, "password": "testpass123", "phone": "555-0100"
    })
    assert response.status_code == 200, response.text
    data = response.json()
    return data["user"], {"Authorization": f"Bearer {data['token']}"}


@pytest.fixture(scope="module")
def staff(api):
    response = api.post(f"{BASE_URL}/api/auth/login", json=STAFF)
    assert response.status_code == 200, response.text
    data = response.json()
    return data["user"], {"Authorization": f"Bearer {data['token']}"}


def test_health_and_auth_contract(api, customer):
    response = api.get(f"{BASE_URL}/api/")
    assert response.status_code == 200 and response.json()["message"]
    user, headers = customer
    me = api.get(f"{BASE_URL}/api/auth/me", headers=headers)
    assert me.status_code == 200 and me.json()["email"] == user["email"]


def test_vehicle_crud_and_booking_persistence(api, customer):
    _, headers = customer
    payload = {"make": "TEST Volvo", "model": "XC60", "year": "2022", "registration_number": "TEST-123", "notes": "test notes"}
    created = api.post(f"{BASE_URL}/api/vehicles", json=payload, headers=headers)
    assert created.status_code == 200 and created.json()["make"] == payload["make"]
    vehicle_id = created.json()["id"]
    listed = api.get(f"{BASE_URL}/api/vehicles", headers=headers)
    assert listed.status_code == 200 and any(v["id"] == vehicle_id for v in listed.json())
    updated_payload = {**payload, "model": "TEST XC90"}
    updated = api.put(f"{BASE_URL}/api/vehicles/{vehicle_id}", json=updated_payload, headers=headers)
    assert updated.status_code == 200 and updated.json()["model"] == "TEST XC90"
    booking = api.post(f"{BASE_URL}/api/bookings", json={
        "vehicle_id": vehicle_id, "service_type": "Oil Change", "appointment_date": "2099-12-01", "appointment_time": "10:30", "notes": "test booking"
    }, headers=headers)
    assert booking.status_code == 200 and booking.json()["status"] == "Pending"
    assert any(b["id"] == booking.json()["id"] for b in api.get(f"{BASE_URL}/api/bookings", headers=headers).json())


def test_staff_can_update_booking_and_customer_can_review(api, customer, staff):
    _, customer_headers = customer
    _, staff_headers = staff
    vehicles = api.get(f"{BASE_URL}/api/vehicles", headers=customer_headers).json()
    bookings = api.get(f"{BASE_URL}/api/bookings", headers=customer_headers).json()
    assert vehicles and bookings
    booking_id = bookings[-1]["id"]
    forbidden = api.patch(f"{BASE_URL}/api/bookings/{booking_id}", json={"status": "Completed"}, headers=customer_headers)
    assert forbidden.status_code == 403
    changed = api.patch(f"{BASE_URL}/api/bookings/{booking_id}", json={"status": "Completed", "price": 125.5, "payment_status": "Paid"}, headers=staff_headers)
    assert changed.status_code == 200 and changed.json()["status"] == "Completed" and changed.json()["price"] == 125.5
    review = api.post(f"{BASE_URL}/api/reviews", json={"booking_id": booking_id, "rating": 5, "comment": "TEST excellent service"}, headers=customer_headers)
    assert review.status_code == 200 and review.json()["rating"] == 5
    duplicate = api.post(f"{BASE_URL}/api/reviews", json={"booking_id": booking_id, "rating": 4, "comment": "TEST duplicate"}, headers=customer_headers)
    assert duplicate.status_code == 400


def test_profile_update_and_role_protection(api, customer, staff):
    _, customer_headers = customer
    _, staff_headers = staff
    profile = api.put(f"{BASE_URL}/api/profile", json={"name": "TEST Updated", "phone": "555-9999", "address": "TEST Address"}, headers=customer_headers)
    assert profile.status_code == 200 and profile.json()["name"] == "TEST Updated"
    no_auth = api.get(f"{BASE_URL}/api/bookings")
    assert no_auth.status_code == 401
    staff_vehicles = api.get(f"{BASE_URL}/api/vehicles", headers=staff_headers)
    assert staff_vehicles.status_code == 200