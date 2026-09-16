struct GameConfig
{
    int threshold;
    int flags;
    unsigned int max_players;
};

struct GameConfig g_config = {10, 0, 4};

static const int g_threshold_table[4] = {5, 10, 20, 40};

int function1(void)
{
    return g_config.threshold + g_threshold_table[g_config.flags];
}
