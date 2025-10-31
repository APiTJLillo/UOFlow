#include <cassert>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "Net/ScannerStage3.hpp"

using Net::Scanner::CandidateDescriptor;
using Net::Scanner::PrioritizeCandidates;
using Net::Scanner::RejectStore;
using Net::Scanner::SampleAggregate;
using Net::Scanner::SendSample;
using Net::Scanner::SendSampleRing;
using Net::Scanner::ScanPassTelemetry;
using Net::Scanner::TokenBucket;
using Net::Scanner::TrustedEndpointCache;
using Net::Scanner::Tuner;

static void TestSamplePrioritization()
{
    SendSampleRing ring;
    SendSample sample{};
    sample.ts_ms = 1;
    sample.callsite = 0x12345678u;
    sample.ip = 0x0A000001u;
    sample.port = 7777;
    sample.sock = 42;
    assert(ring.push(sample));

    std::vector<SendSample> drained;
    ring.drain(drained);
    assert(drained.size() == 1);

    std::unordered_map<std::uint64_t, SampleAggregate> aggregates;
    auto& agg = aggregates[sample.callsite];
    agg.callsite = sample.callsite;
    agg.ip = sample.ip;
    agg.port = sample.port;
    agg.sock = sample.sock;
    agg.count = 1;
    agg.last_ts_ms = sample.ts_ms;

    CandidateDescriptor eager{};
    eager.endpoint = reinterpret_cast<void*>(0x2000);
    eager.sampleReferenced = true;
    eager.sampleCount = agg.count;

    CandidateDescriptor fallback{};
    fallback.endpoint = reinterpret_cast<void*>(0x3000);

    std::vector<CandidateDescriptor> descriptors{fallback, eager};
    PrioritizeCandidates(descriptors);
    assert(descriptors.front().endpoint == eager.endpoint);
}

static void TestTrustedEndpointCache()
{
    TrustedEndpointCache cache;
    const std::uint64_t callsite = 0xCAFEBABEull;
    const std::uint32_t ip = 0x7F000001u;
    const std::uint16_t port = 2593;
    const std::uint32_t sock = 55;
    const std::uintptr_t endpoint = 0x5000;

    cache.addOrRefresh(callsite, ip, port, sock, endpoint, true, 100);
    auto lookup = cache.lookupByEndpoint(endpoint);
    assert(lookup.has_value());
    assert(lookup->accept_count == 1);

    cache.addOrRefresh(callsite, ip, port, sock, endpoint, true, 200);
    lookup = cache.lookup(callsite, ip, port);
    assert(lookup.has_value());
    assert(lookup->accept_count == 2);
    assert(lookup->last_seen_ms == 200);
}

static void TestRejectStoreTtl()
{
    RejectStore store;
    const std::uintptr_t addr = 0x7000;

    auto r1 = store.incrementReject(addr, 0);
    assert(r1.first == 1 && r1.second == 10);

    auto r2 = store.incrementReject(addr, 0);
    assert(r2.first == 2 && r2.second == 60);

    auto r3 = store.incrementReject(addr, 0);
    assert(r3.first == 3 && r3.second == 300);

    auto r4 = store.incrementReject(addr, 0);
    assert(r4.first == 4 && r4.second == 3600);

    auto r5 = store.incrementReject(addr, 0);
    assert(r5.first == 5 && r5.second == 3600);

    assert(store.isRejectedAndActive(addr, 1000));
}

static void TestTunerAdjustments()
{
    Tuner tuner;

    ScanPassTelemetry telemetry{};
    telemetry.candidates_considered = 10;
    telemetry.rejected = 8;
    telemetry.accepted = 2;
    telemetry.total_candidate_us = 900000; // 90k average
    telemetry.ring_load_pct = 85;

    const std::uint32_t beforeDelay = tuner.stepDelayMs();
    const std::uint32_t beforeInflight = tuner.maxInflight();

    tuner.applyTelemetry(telemetry);

    assert(tuner.stepDelayMs() >= beforeDelay + 30);
    assert(tuner.maxInflight() == beforeInflight - 1);
}

int main()
{
    TestSamplePrioritization();
    TestTrustedEndpointCache();
    TestRejectStoreTtl();
    TestTunerAdjustments();
    return 0;
}
