#include <cassert>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "Net/ScannerStage3.hpp"

using Net::Scanner::CandidateDescriptor;
using Net::Scanner::PrioritizeCandidates;
using Net::Scanner::RejectStore;
using Net::Scanner::SendSample;
using Net::Scanner::SendSampleRing;
using Net::Scanner::SampleDeduper;
using Net::Scanner::ScanPassTelemetry;
using Net::Scanner::TokenBucket;
using Net::Scanner::EndpointTrustCache;
using Net::Scanner::RejectStore;
using Net::Scanner::Tuner;

static void TestSamplePrioritization()
{
    SendSampleRing ring;
    SendSample sample{};
    sample.tick = 1;
    sample.func = reinterpret_cast<void*>(0x1000);
    sample.ret = reinterpret_cast<void*>(0x2000);
    assert(ring.push(sample));

    std::vector<SendSample> drained;
    ring.drain(drained);
    assert(drained.size() == 1);
}

static void TestSampleDeduper()
{
    SampleDeduper dedupe;
    const std::uint64_t now = 1000;
    assert(dedupe.accept(0x400000, 0x1234, now));
    assert(!dedupe.accept(0x400000, 0x1234, now + 200));
    assert(dedupe.accept(0x400000, 0x1234, now + 2000));
}

static void TestEndpointTrustCache()
{
    EndpointTrustCache cache;
    EndpointTrustCache::SlotKey slotKey{reinterpret_cast<void*>(0x4000),
                                        reinterpret_cast<void*>(0x5000),
                                        3};
    EndpointTrustCache::CodeKey codeKey{0x2000};

    cache.store(slotKey, true, 1000, 60000);
    auto slotHit = cache.lookup(slotKey, 2000);
    assert(slotHit.has_value());
    assert(slotHit->accepted);
    auto managerHit = cache.lookupByManager(slotKey.manager, 2000);
    assert(managerHit.has_value());
    assert(managerHit->trust.acceptCount == 1);

    cache.store(slotKey, true, 3000, 60000);
    auto slotHit2 = cache.lookup(slotKey, 4000);
    assert(slotHit2.has_value());
    assert(slotHit2->trust.acceptCount == 2);

    const std::uint64_t expireTick = slotHit2->trust.ttlExpiryMs + 1;
    assert(!cache.lookupByManager(slotKey.manager, expireTick).has_value());

    cache.store(codeKey, false, 1000, 1000);
    auto codeHit = cache.lookup(codeKey, 1500);
    assert(codeHit.has_value());
    assert(!codeHit->accepted);
    assert(!cache.lookup(codeKey, 3000).has_value());
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
    TestSampleDeduper();
    TestEndpointTrustCache();
    TestRejectStoreTtl();
    TestTunerAdjustments();
    return 0;
}
