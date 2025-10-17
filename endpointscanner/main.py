import logging
import aiohttp
import asyncio
from cli import cli_main, close_global_session


def setup_logger():
    """Configure logging for the main entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [main] %(message)s',
        datefmt='%H:%M:%S'
    )

async def main():
    """Main entry point of the program."""
    logging.info("Starting CLI tool...")
    try:
        await cli_main()
        # when done with all checks in your whole program
        await close_global_session()
        logging.info("CLI tool finished successfully.")
    except Exception as e:
        logging.exception(f"An error occurred while running CLI tool: {e}")

if __name__ == '__main__':
    setup_logger()
    # Correctly run the async function
    try:
        asyncio.run(main()) 
    except KeyboardInterrupt:
        logging.info("Program interrupted by user.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
