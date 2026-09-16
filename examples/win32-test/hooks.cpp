struct Counter
{
    int value;
    void bump()
    {
        value += 1;
    }
};

static Counter g_counter = {0};

extern "C" void function2(void)
{
    g_counter.bump();
}
