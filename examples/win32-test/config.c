struct GameConfig
{
    int threshold;
    int flags;
    unsigned int max_players;
};

struct GameConfig g_config = {10, 0, 4};

int function1(void)
{
    return g_config.threshold;
}
