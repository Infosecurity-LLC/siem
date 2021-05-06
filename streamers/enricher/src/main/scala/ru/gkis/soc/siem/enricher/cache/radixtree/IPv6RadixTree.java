package ru.gkis.soc.siem.enricher.cache.radixtree;

import com.google.common.net.InetAddresses;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;

public class IPv6RadixTree extends AbstractRadixTree<BigInteger> implements Serializable {
    // Ipv6 start value
    // 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    private static final BigInteger IPV6_START_VALUE = new BigInteger("170141183460469231731687303715884105728");
    // Ipv6 end value
    // 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    private static final BigInteger IPV6_END_VALUE = new BigInteger("340282366920938463463374607431768211455");
    private static final int CIDR_MAX_LENGTH = 128;

    public IPv6RadixTree() {
        init(2048);
    }

    public IPv6RadixTree(int allocatedSize) {
        init(allocatedSize);
    }

    @Override
    public void put(BigInteger key, BigInteger mask, long value) {
        BigInteger bit = IPV6_START_VALUE;
        int node = ROOT_PTR;
        int next = ROOT_PTR;

        while ((bit.and(mask)).compareTo(BigInteger.ZERO) != 0) {
            next = (key.and(bit)).compareTo(BigInteger.ZERO) != 0 ? rights[node] : lefts[node];
            if (next == NULL_PTR)
                break;
            bit = bit.shiftRight(1);
            node = next;
        }

        if (next != NULL_PTR) {
            values[node] = value;
            return;
        }

        while ((bit.and(mask)).compareTo(BigInteger.ZERO) != 0) {
            if (size == allocatedSize) {
                expandAllocatedSize();
            }
            next = size;
            values[next] = NO_VALUE;
            rights[next] = NULL_PTR;
            lefts[next] = NULL_PTR;

            if ((key.and(bit)).compareTo(BigInteger.ZERO) != 0) {
                rights[node] = next;
            } else {
                lefts[node] = next;
            }

            bit = bit.shiftRight(1);
            node = next;
            size++;
        }

        values[node] = value;
    }

    @Override
    public long selectValue(BigInteger key) {
        BigInteger bit = IPV6_START_VALUE;
        long value = NO_VALUE;
        int node = ROOT_PTR;

        while (node != NULL_PTR) {
            if (values[node] != NO_VALUE) {
                value = values[node];
            }
            node = (key.and(bit)).compareTo(BigInteger.ZERO) != 0 ? rights[node] : lefts[node];
            bit = bit.shiftRight(1);
        }

        if (value == NO_VALUE) {
            return NO_VALUE;
        } else {
            return value;
        }
    }

    @Override
    public void put(InetAddress address, String netMaskStr, long value) {
        BigInteger ip = new BigInteger(1, address.getAddress());

        int cidr = 0;
        try {
            cidr = Integer.parseInt(netMaskStr.trim());
        } catch (NumberFormatException e) {
            System.err.println("Incorrect net mask [" + netMaskStr + "] for IP [" + address.toString() + "]");
        }

        BigInteger temp = (new BigInteger("1").shiftLeft(CIDR_MAX_LENGTH - cidr)).subtract(new BigInteger("1"));

        BigInteger netMask = temp.xor(IPV6_END_VALUE);
        put(ip, netMask, value);
    }

    @Override
    public long selectValue(InetAddress ip) {
        return selectValue(new BigInteger(1, ip.getAddress()));
    }

    @Override
    protected BigInteger ipToKey(String ip) {
        return new BigInteger(1, InetAddresses.forString(ip).getAddress());
    }
}