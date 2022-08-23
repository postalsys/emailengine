'use strict';

const TIMEZONE_ABBREVATIONS = {
    ACDT: '+1030',
    ACST: '+0930',
    ACT: '+0800',
    ADT: '-0300',
    AEDT: '+1100',
    AEST: '+1000',
    AFT: '+0430',
    AKDT: '-0800',
    AKST: '-0900',
    AMST: '-0300',
    AMT: '+0400',
    ART: '-0300',
    AST: '+0300',
    AWDT: '+0900',
    AWST: '+0800',
    AZOST: '-0100',
    AZT: '+0400',
    BDT: '+0800',
    BIOT: '+0600',
    BIT: '-1200',
    BOT: '-0400',
    BRT: '-0300',
    BST: '+0600',
    BTT: '+0600',
    CAT: '+0200',
    CCT: '+0630',
    CDT: '-0500',
    CEDT: '+0200',
    CEST: '+0200',
    CET: '+0100',
    CHADT: '+1345',
    CHAST: '+1245',
    CHOT: '+0800',
    CHST: '+1000',
    CHUT: '+1000',
    CIST: '-0800',
    CIT: '+0800',
    CKT: '-1000',
    CLST: '-0300',
    CLT: '-0400',
    COST: '-0400',
    COT: '-0500',
    CST: '-0600',
    CT: '+0800',
    CVT: '-0100',
    CWST: '+0845',
    CXT: '+0700',
    DAVT: '+0700',
    DDUT: '+1000',
    DFT: '+0100',
    EASST: '-0500',
    EAST: '-0600',
    EAT: '+0300',
    ECT: '-0500',
    EDT: '-0400',
    EEDT: '+0300',
    EEST: '+0300',
    EET: '+0200',
    EGST: '+0000',
    EGT: '-0100',
    EIT: '+0900',
    EST: '-0500',
    FET: '+0300',
    FJT: '+1200',
    FKST: '-0300',
    FKT: '-0400',
    FNT: '-0200',
    GALT: '-0600',
    GAMT: '-0900',
    GET: '+0400',
    GFT: '-0300',
    GILT: '+1200',
    GIT: '-0900',
    GMT: '+0000',
    GST: '+0400',
    GYT: '-0400',
    HADT: '-0900',
    HAEC: '+0200',
    HAST: '-1000',
    HKT: '+0800',
    HMT: '+0500',
    HOVT: '+0700',
    HST: '-1000',
    ICT: '+0700',
    IDT: '+0300',
    IOT: '+0300',
    IRDT: '+0430',
    IRKT: '+0900',
    IRST: '+0330',
    IST: '+0530',
    JST: '+0900',
    KGT: '+0600',
    KOST: '+1100',
    KRAT: '+0700',
    KST: '+0900',
    LHST: '+1030',
    LINT: '+1400',
    MAGT: '+1200',
    MART: '-0930',
    MAWT: '+0500',
    MDT: '-0600',
    MET: '+0100',
    MEST: '+0200',
    MHT: '+1200',
    MIST: '+1100',
    MIT: '-0930',
    MMT: '+0630',
    MSK: '+0400',
    MST: '-0700',
    MUT: '+0400',
    MVT: '+0500',
    MYT: '+0800',
    NCT: '+1100',
    NDT: '-0230',
    NFT: '+1130',
    NPT: '+0545',
    NST: '-0330',
    NT: '-0330',
    NUT: '-1100',
    NZDT: '+1300',
    NZST: '+1200',
    OMST: '+0700',
    ORAT: '+0500',
    PDT: '-0700',
    PET: '-0500',
    PETT: '+1200',
    PGT: '+1000',
    PHOT: '+1300',
    PHT: '+0800',
    PKT: '+0500',
    PMDT: '-0200',
    PMST: '-0300',
    PONT: '+1100',
    PST: '-0800',
    PYST: '-0300',
    PYT: '-0400',
    RET: '+0400',
    ROTT: '-0300',
    SAKT: '+1100',
    SAMT: '+0400',
    SAST: '+0200',
    SBT: '+1100',
    SCT: '+0400',
    SGT: '+0800',
    SLST: '+0530',
    SRT: '-0300',
    SST: '+0800',
    SYOT: '+0300',
    TAHT: '-1000',
    THA: '+0700',
    TFT: '+0500',
    TJT: '+0500',
    TKT: '+1300',
    TLT: '+0900',
    TMT: '+0500',
    TOT: '+1300',
    TVT: '+1200',
    UCT: '+0000',
    ULAT: '+0800',
    UTC: '+0000',
    UYST: '-0200',
    UYT: '-0300',
    UZT: '+0500',
    VET: '-0430',
    VLAT: '+1000',
    VOLT: '+0400',
    VOST: '+0600',
    VUT: '+1100',
    WAKT: '+1200',
    WAST: '+0200',
    WAT: '+0100',
    WEDT: '+0100',
    WEST: '+0100',
    WET: '+0000',
    WST: '+0800',
    YAKT: '+1000',
    YEKT: '+0600',
    Z: '+0000'
};

function parseDate(str, defaultDate) {
    if (isValidDate(str)) {
        return str;
    }

    str = (str || '').toString().trim();

    let date = new Date(str);

    if (isValidDate(date)) {
        return date;
    }

    // Assume last alpha part is a timezone
    // Ex: "Date: Thu, 15 May 2014 13:53:30 EEST"
    str = str.replace(/\b[a-z]+$/i, tz => {
        tz = tz.toUpperCase();
        if (TIMEZONE_ABBREVATIONS.hasOwnProperty(tz)) {
            return TIMEZONE_ABBREVATIONS[tz];
        }
        return tz;
    });

    date = new Date(str);

    if (isValidDate(date)) {
        return date;
    } else {
        return defaultDate || new Date();
    }
}

/**
 * Checks if a value is a Date object and it contains an actual date value
 * @param {Date} date Date object to check
 * @returns {Boolean} True if the value is a valid date
 */
function isValidDate(date) {
    return Object.prototype.toString.call(date) === '[object Date]' && date.toString() !== 'Invalid Date';
}

module.exports = parseDate;
