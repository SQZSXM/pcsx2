// VIF1 capture logger for PCSX2 (route A).
// Header-only on purpose: drop it next to the three hook sites and include it.
//
// Record stream (little-endian, x86 native):
//   header : "VIFCAP01"                        (8 bytes)
//   record : u8 type | u8 pad[3] | u32 len | payload[len]
//     type 1 MEM  : u32 addr | bytes        (VU1 data-memory image after a VIF UNPACK)
//     type 2 TOP  : u32 value               (XTOP cursor)
//     type 3 ITOP : u32 value               (XITOP cursor / "data available")
//     type 4 KICK : u32 addr | bytes        (XGKICK packet as sent to GIF)
//     type 5 FRAME: u32 index               (optional marker)
//
// Build notes: disable MTVU and Instant VU1 for a deterministic capture.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace vifcap {

enum : uint8_t { REC_MEM = 1, REC_TOP = 2, REC_ITOP = 3, REC_KICK = 4, REC_FRAME = 5, REC_VUREGS = 6, REC_MVUCALL = 7, REC_BLOCK = 8 };

inline FILE*& file()
{
    static FILE* f = nullptr;
    return f;
}

inline bool Enabled() { return file() != nullptr; }

inline void Close()
{
    if (file())
    {
        std::fclose(file());
        file() = nullptr;
    }
}

inline void Open(const char* path)
{
    Close();
    file() = std::fopen(path, "wb");
    if (file())
        std::fwrite("VIFCAP01", 1, 8, file());
}

inline void Rec(uint8_t type, const void* a, uint32_t alen, const void* b, uint32_t blen)
{
    if (!file())
        return;
    std::fwrite(&type, 1, 1, file());
    const uint8_t pad[3] = {0, 0, 0};
    std::fwrite(pad, 1, 3, file());
    const uint32_t len = alen + blen;
    std::fwrite(&len, 4, 1, file());
    if (alen)
        std::fwrite(a, 1, alen, file());
    if (blen)
        std::fwrite(b, 1, blen, file());
}

inline void Mem(uint32_t addr, const void* data, uint32_t len) { Rec(REC_MEM, &addr, 4, data, len); }
inline void Top(uint32_t v) { Rec(REC_TOP, &v, 4, nullptr, 0); }
inline void Itop(uint32_t v) { Rec(REC_ITOP, &v, 4, nullptr, 0); }
inline void Kick(uint32_t addr, const void* data, uint32_t len) { Rec(REC_KICK, &addr, 4, data, len); }
inline void Frame(uint32_t n) { Rec(REC_FRAME, &n, 4, nullptr, 0); }
inline void VU1Regs(const void* data, uint32_t len) { Rec(REC_VUREGS, data, len, nullptr, 0); }
inline void Block(uint32_t startpc, uint32_t tpc, uint32_t cycles, uint32_t count)
{
    const uint32_t b[4] = {startpc, tpc, cycles, count};
    Rec(REC_BLOCK, b, sizeof(b), nullptr, 0);
}

inline void MVUCall(uint32_t startpc, uint32_t budget, uint32_t used, uint32_t endtpc, const uint32_t* vi)
{
    uint32_t b[20];
    b[0] = startpc; b[1] = budget; b[2] = used; b[3] = endtpc;
    for (int i = 0; i < 16; i++) b[4 + i] = vi[i];
    Rec(REC_MVUCALL, b, sizeof(b), nullptr, 0);
}

} // namespace vifcap
