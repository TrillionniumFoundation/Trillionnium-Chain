import backtrader as bt
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class FuturesTrendStrategy(bt.Strategy):
    """
    A simple Trend Following strategy for Futures.
    Logic:
    - Long if Fast MA crosses above Slow MA.
    - Close if Fast MA crosses below Slow MA.
    """
    
    params = (
        ('fast_ma', 20),
        ('slow_ma', 50),
        ('printlog', True),
    )

    def log(self, txt, dt=None):
        ''' Logging function '''
        if self.params.printlog:
            dt = dt or self.datas[0].datetime.date(0)
            logging.info(f'{dt.isoformat()}, {txt}')

    def __init__(self):
        # Keep a reference to the "close" line in the data[0] dataseries
        self.dataclose = self.datas[0].close
        self.order = None
        self.buyprice = None
        self.buycomm = None

        # Add MovingAverage indicators
        self.fast_ma = bt.indicators.SimpleMovingAverage(
            self.datas[0], period=self.params.fast_ma)
        self.slow_ma = bt.indicators.SimpleMovingAverage(
            self.datas[0], period=self.params.slow_ma)
            
        # CrossOver signal (1: Long, -1: Short)
        self.crossover = bt.indicators.CrossOver(self.fast_ma, self.slow_ma)

    def notify_order(self, order):
        if order.status in [order.Submitted, order.Accepted]:
            # Buy/Sell order submitted/accepted to/by broker - Nothing to do
            return

        if order.status in [order.Completed]:
            if order.isbuy():
                self.log(f'BUY EXECUTED, Price: {order.executed.price:.2f}, Cost: {order.executed.value:.2f}, Comm: {order.executed.comm:.2f}')
                self.buyprice = order.executed.price
                self.buycomm = order.executed.comm
            else:  # Sell
                self.log(f'SELL EXECUTED, Price: {order.executed.price:.2f}, Cost: {order.executed.value:.2f}, Comm: {order.executed.comm:.2f}')
                
            self.bar_executed = len(self)

        elif order.status in [order.Canceled, order.Margin, order.Rejected]:
            self.log('Order Canceled/Margin/Rejected')

        self.order = None

    def notify_trade(self, trade):
        if not trade.isclosed:
            return

        self.log(f'OPERATION PROFIT, GROSS {trade.pnl:.2f}, NET {trade.pnlcomm:.2f}')

    def next(self):
        # Check if an order is pending ... if yes, we cannot send a 2nd one
        if self.order:
            return

        # Check if we are in the market
        if not self.position:
            # Not in the market, check for signal to ENTER
            if self.crossover > 0:  # Fast crosses above Slow
                self.log(f'BUY CREATE, {self.dataclose[0]:.2f}')
                self.order = self.buy() # Default size is 1 contract

        else:
            # Already in the market, check for signal to EXIT
            if self.crossover < 0:  # Fast crosses below Slow
                self.log(f'SELL CREATE, {self.dataclose[0]:.2f}')
                self.order = self.close() # Close position
