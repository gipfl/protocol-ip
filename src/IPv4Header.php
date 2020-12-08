<?php

namespace gipfl\Protocol\IP;

use gipfl\Protocol\Exception\ProtocolError;
use function long2ip;
use function strlen;
use function substr;
use function unpack;

class IPv4Header
{
    const FLAG_EVIL = 0x04;

    const FLAG_DONT_FRAGMENT = 0x02;

    const FLAG_MORE_FRAGMENTS = 0x01;

    const HEADER_PARTS = 'CversionIhl/Ctos/ntotalLength/nid/nff/Cttl/Cprotocol/nchecksum/Nsource/Ndestination';

    /** @var int */
    protected $version = 4;

    /** @var int Header length in Bytes */
    protected $headerLength;

    /** @var int Total length in Bytes */
    protected $totalLength;

    protected $identification;

    /** @var int */
    protected $ttl;

    /** @var int */
    protected $fragmentationFlags;

    /** @var int */
    protected $fragmentationOffset;

    /** @var int Protocol number, see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml */
    protected $protocol;

    /** @var int differentiated services codepoint */
    protected $dscp;

    /** @var int explicit congestion notification */
    protected $ecn;

    /** @var integer */
    protected $checksum;

    /** @var int binary, 4 bytes */
    protected $source;

    /** @var int binary, 4 bytes */
    protected $destination;

    protected $rawString;

    protected function __construct()
    {
    }

    public static function parse($packet)
    {
        return (new static())->parsePacketString($packet);
    }

    /**
     * IP Version
     *
     * @return int
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * Header length in Bytes
     *
     * @return int
     */
    public function getHeaderLength()
    {
        return $this->headerLength;
    }

    /**
     * @return int Total length in Bytes
     */
    public function getTotalLength()
    {
        return $this->totalLength;
    }

    /**
     * Protocol number, see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
     *
     * @return int
     */
    public function getProtocol()
    {
        return $this->protocol;
    }

    /**
     * @return int Bytes
     */
    public function getPayloadLength()
    {
        return $this->totalLength - $this->headerLength;
    }

    /**
     * @return string
     */
    public function getSourceIp()
    {
        return long2ip($this->source);
    }

    /**
     * @return string
     */
    public function getDestinationIp()
    {
        return long2ip($this->destination);
    }

    /**
     * @return int
     */
    public function getTimeToLive()
    {
        return $this->ttl;
    }

    /**
     * Whether the "Don't Fragment" bit has NOT been set
     *
     * @return bool
     */
    public function allowsFragmentation()
    {
        return ($this->fragmentationFlags & self::FLAG_DONT_FRAGMENT) === 0;
    }

    /**
     * Whether there are more fragments of this packet
     *
     * @return bool
     */
    public function hasMoreFragments()
    {
        return ($this->fragmentationFlags & self::FLAG_MORE_FRAGMENTS) === self::FLAG_MORE_FRAGMENTS;
    }

    /**
     * The Security Flag in the IPv4 header
     *
     * https://tools.ietf.org/html/rfc3514
     *
     * @return bool
     */
    public function isEvil()
    {
        return ($this->fragmentationFlags & self::FLAG_EVIL) === self::FLAG_EVIL;
    }

    /**
     * @return int
     */
    public function getFragmentationOffset()
    {
        return $this->fragmentationOffset;
    }

    protected function parsePacketString($packet)
    {
        $length = strlen($packet);
        if ($length < 20) {
            throw new ProtocolError("IPv4 headers must be at least 20 Bytes long, got $length");
        }
        $parts = unpack(self::HEADER_PARTS, substr($packet, 0, 20));
        $this->parseVersionIhl($parts['versionIhl']);
        $this->parseTos($parts['tos']);
        $this->parseFragmentation($parts['ff']);
        $this->identification = $parts['id'];
        $this->ttl            = $parts['ttl'];
        $this->totalLength    = $parts['totalLength'];
        $this->protocol       = $parts['protocol'];
        $this->checksum       = $parts['checksum'];
        $this->source         = $parts['source'];
        $this->destination    = $parts['destination'];
        if ($length < $this->headerLength) {
            throw new ProtocolError(sprintf(
                "IPv4 headers declares %d Bytes, got only %d",
                $this->headerLength,
                $length
            ));
        }

        $this->rawString = substr($packet, 0, $this->headerLength);

        return $this;
    }

    protected function parseFragmentation($unsignedShort)
    {
        // first three bits
        $this->fragmentationFlags = ($unsignedShort & 0xe000) >> 13;
        // last 13 bits, bit-shifted as this is x8
        $this->fragmentationOffset = ($unsignedShort & 0x1fff) << 3;
    }

    protected function parseVersionIhl($character)
    {
        $version = ($character & 0xf0) >> 4;
        if ($version !== 4) {
            throw new ProtocolError("IPv4 header expected, got IPv$version");
        }

        // number of 32-bit words in the header, therefore we multiply with 4 (left-shift 2)
        $this->headerLength = ($character & 0x0f) << 2;
    }

    protected function parseTos($tos)
    {
        // First 6 bits:
        $this->dscp = ($tos & 0xfc) >> 2;
        $this->ecn = $tos & 0x03;
    }
}
