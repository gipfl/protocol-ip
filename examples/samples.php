<?php

use gipfl\Protocol\IP\IPv4Header;

require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL | E_STRICT);

$headers = [
    // UDP to Multicast address
    '45000097b55f000004119e52c0000206effffffa',
    // TCP (TLS) packet, fragmentation not allowed
    '450000aea00d4000360679d5c000021ac000020a',
    // Normal ICMP echo request (ping)
    '450000548cfa400040012a98c000020a08080808',
    // Ping with 8 Byte header, 2000 byte payload, fragmented
    '450005dc22dc20004001af2ec000020a08080808',
    '4500022423da00b94001d12fc000020a08080808',
];

function getProtocolName($protocol)
{
    switch ($protocol) {
        case 1:
            return 'ICMP';
        case 6:
            return 'TCP';
        case 17:
            return 'UDP';
        default:
            return 'protocol ' . bin2hex($protocol);
    }
}

function showIpHeaderInfo($header)
{
    $header = IPv4Header::parse($header);
    printf(
        "Got a %d byte (%s byte header, %s byte payload) %s packet from %s to %s\n",
        $header->getTotalLength(),
        $header->getHeaderLength(),
        $header->getPayloadLength(),
        getProtocolName($header->getProtocol()),
        $header->getSourceIp(),
        $header->getDestinationIp()
    );
    if ($offset = $header->getFragmentationOffset()) {
        printf("  Fragment at offset %d\n", $offset);
        echo $header->hasMoreFragments()
            ? "  There are more fragments to come\n"
            : "  This is the last fragment of this packet\n";
    } elseif ($header->hasMoreFragments()) {
        echo "  This is the first fragment, more to come\n";
    } else {
        echo "  This packet has not been fragmented\n";
    }
    if ($header->allowsFragmentation()) {
        echo "  Fragmentation is allowed\n";
    } else {
        echo "  Fragmentation is NOT allowed\n";
    }
    printf("  Time to live: %d\n\n", $header->getTimeToLive());
}

foreach ($headers as $header) {
    showIpHeaderInfo(hex2bin($header));
}
