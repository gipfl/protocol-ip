<?php

namespace gipfl\Protocol\IPv4;

class IPv4Header
{
    protected $version;

    protected $tos;

    protected $headerLength;

    protected $totalLength;

    protected $id;

    protected $protocol;

    protected $checksum;

    protected $source;

    protected $destination;

    protected function __construct()
    {
    }

    public static function parse(& $packet)
    {
        $hdr = new static();

        $parts = unpack(
            'CversionIhl/Ctos/ntotalLength/nid/nff/Cttl/Cprotocol/nchecksum/Nsource/Ndestination',
            substr($packet, 0, 20)
        );
        $hdr->version      = $parts['versionIhl'] >> 4;
        $hdr->headerLength = ($parts['versionIhl'] & 0x0f) << 2;
        $hdr->source       = \long2ip($parts['source']);
        $hdr->protocol     = $parts['protocol'];
        $hdr->destination  = \long2ip($parts['destination']);
        $hdr->totalLength  = $parts['totalLength'];

        return $hdr;
    }

    public function getSourceIp()
    {
        return $this->source;
    }

    public function getHeaderLength()
    {
        return $this->headerLength;
    }

    public function getTotalLength()
    {
        return $this->totalLength;
    }

    public function getProtocol()
    {
        return $this->protocol;
    }

    public function getPayloadLength()
    {
        return $this->totalLength - $this->headerLength;
    }

    public function getDestinationIp()
    {
        return $this->destination;
    }
}
