declare module 'proxy-addr' {
  import type { IncomingMessage } from 'node:http';

  type Trust = (address: string, hop: number) => boolean;
  function proxyaddr(request: IncomingMessage, trust: Trust | string | string[]): string;
  namespace proxyaddr {
    function all(request: IncomingMessage, trust?: Trust | string | string[]): string[];
    function compile(trust: string | string[]): Trust;
  }
  export default proxyaddr;
}
