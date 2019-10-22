"""Tests for LLRPClient."""
from __future__ import unicode_literals

import pytest
import sllurp.llrp


def test_get_tx_power_impinj():
    """Test getting TX power on an Impinj reader."""

    client = sllurp.llrp.LLRPClient(None)
    client.tx_power_table = [
        0,
        10.0, 10.25, 10.5, 10.75, 11.0, 11.25, 11.5, 11.75, 12.0, 12.25,
        12.5, 12.75, 13.0, 13.25, 13.5, 13.75, 14.0, 14.25, 14.5, 14.75,
        15.0, 15.25, 15.5, 15.75, 16.0, 16.25, 16.5, 16.75, 17.0, 17.25,
        17.5, 17.75, 18.0, 18.25, 18.5, 18.75, 19.0, 19.25, 19.5, 19.75,
        20.0, 20.25, 20.5, 20.75, 21.0, 21.25, 21.5, 21.75, 22.0, 22.25,
        22.5, 22.75, 23.0, 23.25, 23.5, 23.75, 24.0, 24.25, 24.5, 24.75,
        25.0, 25.25, 25.5, 25.75, 26.0, 26.25, 26.5, 26.75, 27.0, 27.25,
        27.5, 27.75, 28.0, 28.25, 28.5, 28.75, 29.0, 29.25, 29.5, 29.75,
        30.0, 30.25, 30.5, 30.75, 31.0, 31.25, 31.5, 31.75, 32.0, 32.25,
        32.5,
    ]
    assert len(client.tx_power_table) == 92

    assert client.get_tx_power({1: 0}) == {
        1: (len(client.tx_power_table) - 1, max(client.tx_power_table))}

    # spot tests
    assert client.get_tx_power({1: 13}) == {
        1: (13, client.tx_power_table[13])}
    assert client.get_tx_power({1: 36}) == {
        1: (36, client.tx_power_table[36])}


def test_get_tx_power_zebra():
    """Test getting TX power on a Zebra reader.

    Zebra lists 0 (max power) as the final, not the first, entry in the
    tx_power table.
    """
    client = sllurp.llrp.LLRPClient(None)
    client.tx_power_table = [10.0, 10.1, 10.2, 11, 12, 18, 25.0, 29.2, 0]

    assert client.get_tx_power({1: 0}) == {
        1: (len(client.tx_power_table) - 2, max(client.tx_power_table))}

    assert client.get_tx_power({1: 5}) == {
        1: (5, client.tx_power_table[5])}
