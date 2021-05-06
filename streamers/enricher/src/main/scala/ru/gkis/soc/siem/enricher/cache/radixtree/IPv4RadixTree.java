package ru.gkis.soc.siem.enricher.cache.radixtree;

import com.google.common.net.InetAddresses;

import java.io.Serializable;
import java.net.InetAddress;
import java.nio.ByteBuffer;

public class IPv4RadixTree extends AbstractRadixTree<Long> implements Serializable {

    // 10000000000000000000000000000000 --> 32 bit
    private static final long START_BIT = 0x80000000L;
    // 11111111111111111111111111111111 --> 32 bit
    private static final long END_BIT = 0xffffffffL;
    private static final int CIDR_MAX_LENGTH = 32;

    public IPv4RadixTree() {
        init(1024);
    }

    public IPv4RadixTree(int allocatedSize) {
        init(allocatedSize);
    }

    @Override
    public void put(Long key, Long mask, long value) {
        long bit = START_BIT;
        int node = ROOT_PTR;
        int next = ROOT_PTR;

        while ((bit & mask) != 0) {
            next = ((key & bit) != 0) ? rights[node] : lefts[node];
            if (next == NULL_PTR)
                break;
            bit >>= 1;
            node = next;
        }

        if (next != NULL_PTR) {
            values[node] = value;
            return;
        }

        while ((bit & mask) != 0) {
            if (size == allocatedSize) {
                expandAllocatedSize();
            }
            next = size;
            values[next] = NO_VALUE;
            rights[next] = NULL_PTR;
            lefts[next] = NULL_PTR;

            if ((key & bit) != 0) {
                rights[node] = next;
            } else {
                lefts[node] = next;
            }

            bit >>= 1;
            node = next;
            size++;
        }

        values[node] = value;
    }

    @Override
    public long selectValue(Long key) {
        long bit = START_BIT;
        long value = NO_VALUE;
        int node = ROOT_PTR;

        while (node != NULL_PTR) {
            if (values[node] != NO_VALUE) {
                value = values[node];
            }
            node = ((key & bit) != 0) ? rights[node] : lefts[node];
            bit >>= 1;
        }

        if (value == NO_VALUE) {
            return NO_VALUE;
        } else {
            return value;
        }
    }

    @Override
    public void put(InetAddress address, String netMaskStr, long value) {
        long ip = ByteBuffer.wrap(address.getAddress()).getInt();
        int cidr = 0;
        try {
            cidr = Integer.parseInt(netMaskStr.trim());
        } catch (NumberFormatException e) {
            System.err.println("Incorrect net mask [" + netMaskStr + "] for IP [" + address.toString() + "]");
        }

        long netMask = ((1L << (CIDR_MAX_LENGTH - cidr)) - 1L) ^ END_BIT;
        put(ip, netMask, value);
    }

    @Override
    public long selectValue(InetAddress ip) {
        return selectValue((long) ByteBuffer.wrap(ip.getAddress()).getInt());
    }

    @Override
    protected Long ipToKey(String ip) {
        return (long) ByteBuffer.wrap(InetAddresses.forString(ip).getAddress()).getInt();
    }
}
